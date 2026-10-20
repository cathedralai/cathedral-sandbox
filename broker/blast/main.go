// blast: send N room creates at once through central booking, hold the rooms
// with heartbeats and a light exec on a sample, then stop heartbeats and watch
// the hotels clean up. Writes results.json and timeline.csv to -out.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	Status     int     `json:"status"`
	ID         string  `json:"id,omitempty"`
	Hotel      string  `json:"hotel,omitempty"`
	ClientMs   float64 `json:"client_ms"`
	QueueMs    float64 `json:"queue_ms"`
	HotelMs    float64 `json:"hotel_ms"`
	OverheadMs float64 `json:"overhead_ms"`
	DoneAtMs   float64 `json:"done_at_ms"` // since blast start
	Err        string  `json:"err,omitempty"`
}

var (
	base   string
	key    string
	client = &http.Client{Transport: &http.Transport{MaxIdleConns: 10000, MaxIdleConnsPerHost: 10000, IdleConnTimeout: 5 * time.Minute}}
)

func call(ctx context.Context, method, path string, body any) (int, http.Header, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, base+path, rd)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, out, nil
}

func f(h http.Header, k string) float64 { v, _ := strconv.ParseFloat(h.Get(k), 64); return v }

func pct(xs []float64) map[string]float64 {
	if len(xs) == 0 {
		return map[string]float64{"n": 0}
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	at := func(p float64) float64 { return s[int(p*float64(len(s)-1))] }
	return map[string]float64{"n": float64(len(s)), "p50": at(.5), "p95": at(.95), "p99": at(.99), "max": s[len(s)-1]}
}

type hotelStat struct {
	ID          string  `json:"id"`
	OK          bool    `json:"ok"`
	Running     int     `json:"broker_running"`
	APIRunning  int     `json:"api_running"`
	APIDeleting int     `json:"api_deleting"`
	Containers  int     `json:"containers"`
	CPU         float64 `json:"cpu_pct"`
	Mem         float64 `json:"mem_pct"`
	MemGiB      float64 `json:"mem_gib"`
	Load1       float64 `json:"load1"`
	Queued      int     `json:"queued"`
	Creating    int     `json:"creating"`
}

func stats(ctx context.Context) ([]hotelStat, map[string]any) {
	st, _, out, err := call(ctx, "GET", "/v1/broker/stats", nil)
	if err != nil || st != 200 {
		return nil, nil
	}
	var doc struct {
		Hotels []hotelStat `json:"hotels"`
	}
	var raw map[string]any
	_ = json.Unmarshal(out, &doc)
	_ = json.Unmarshal(out, &raw)
	return doc.Hotels, raw
}

func main() {
	flag.StringVar(&base, "url", "http://127.0.0.1:18100", "central booking base URL")
	keyFile := flag.String("keyfile", "", "file with the guest key")
	n := flag.Int("n", 4000, "rooms to create at once")
	image := flag.String("image", "alpine:3.20", "room image")
	ttl := flag.Int("ttl", 600, "room TTL seconds")
	hold := flag.Duration("hold", 5*time.Minute, "hold with heartbeats after all creates return")
	hbEvery := flag.Duration("hb", 2*time.Minute, "heartbeat interval during hold")
	sample := flag.Int("sample", 200, "rooms that get a periodic exec")
	execEvery := flag.Duration("exec", 30*time.Second, "exec interval for the sample")
	watch := flag.Duration("watch", 40*time.Minute, "max time to watch cleanup")
	memStop := flag.Float64("memstop", 90, "abort if any hotel RAM % is above this")
	outDir := flag.String("out", ".", "output directory")
	stopFile := flag.String("stopfile", "", "abort when this file exists")
	netCheck := flag.Int("netcheck", 0, "rooms that fetch a public URL once at the start of the hold")
	finalTTL := flag.Int("final-ttl", 0, "TTL set by the last heartbeat before cleanup (0 = -ttl)")
	network := flag.String("network", "public", "room network mode: public or none (none uses no bridge port)")
	flag.Parse()
	k, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal("key file: ", err)
	}
	key = strings.TrimSpace(string(k))
	run := time.Now().UTC().Format("20060102T150405")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = os.MkdirAll(*outDir, 0o755)
	tl, _ := os.Create(filepath.Join(*outDir, "timeline.csv"))
	defer tl.Close()
	fmt.Fprintln(tl, "t_s,phase,hotel,ok,broker_running,api_running,api_deleting,containers,cpu_pct,mem_pct,mem_gib,load1,queued,creating")

	var phase atomic.Value
	phase.Store("baseline")
	var aborted atomic.Value
	aborted.Store("")
	t0 := time.Now()
	peaks := map[string]map[string]float64{}
	var pmu sync.Mutex
	// Monitor: timeline every 2 s and the safety stop.
	go func() {
		for {
			hs, _ := stats(context.Background())
			ts := time.Since(t0).Seconds()
			pmu.Lock()
			for _, h := range hs {
				fmt.Fprintf(tl, "%.1f,%s,%s,%v,%d,%d,%d,%d,%.1f,%.1f,%.1f,%.1f,%d,%d\n", ts, phase.Load(), h.ID, h.OK, h.Running, h.APIRunning, h.APIDeleting, h.Containers, h.CPU, h.Mem, h.MemGiB, h.Load1, h.Queued, h.Creating)
				p := peaks[h.ID]
				if p == nil {
					p = map[string]float64{}
					peaks[h.ID] = p
				}
				for kk, v := range map[string]float64{"cpu_pct": h.CPU, "mem_pct": h.Mem, "mem_gib": h.MemGiB, "load1": h.Load1, "containers": float64(h.Containers), "api_running": float64(h.APIRunning)} {
					if v > p[kk] {
						p[kk] = v
					}
				}
				if h.Mem > *memStop && aborted.Load() == "" {
					aborted.Store(fmt.Sprintf("hotel %s RAM %.1f%% > %.0f%%", h.ID, h.Mem, *memStop))
					cancel()
				}
			}
			pmu.Unlock()
			if *stopFile != "" {
				if _, err := os.Stat(*stopFile); err == nil && aborted.Load() == "" {
					aborted.Store("stop file present")
					cancel()
				}
			}
			tl.Sync()
			time.Sleep(2 * time.Second)
		}
	}()
	time.Sleep(4 * time.Second)
	_, _, _, _ = call(context.Background(), "POST", "/v1/broker/stats", nil) // reset broker counters

	// Phase 1: all creates at once.
	phase.Store("create")
	body := map[string]any{"image": *image, "resources": map[string]any{"vcpu": 1, "memory_gib": 4, "disk_gib": 10},
		"ttl_seconds": *ttl, "labels": map[string]string{"run": run, "kind": "blast"}, "network": map[string]any{"mode": *network}}
	res := make([]result, *n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < *n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			t := time.Now()
			st, h, out, err := call(ctx, "POST", "/v1/sandboxes", body)
			r := result{Status: st, ClientMs: float64(time.Since(t).Microseconds()) / 1000, DoneAtMs: float64(time.Since(tStart).Microseconds()) / 1000}
			if err != nil {
				r.Err = err.Error()
			} else {
				r.Hotel, r.QueueMs, r.HotelMs, r.OverheadMs = h.Get("X-Broker-Hotel"), f(h, "X-Broker-Queue-Ms"), f(h, "X-Broker-Hotel-Ms"), f(h, "X-Broker-Overhead-Ms")
				var doc map[string]any
				_ = json.Unmarshal(out, &doc)
				r.ID, _ = doc["id"].(string)
				if st != 202 {
					r.Err = string(out[:min(len(out), 300)])
				}
			}
			res[i] = r
		}(i)
	}
	tStart = time.Now()
	createStartS := time.Since(t0).Seconds()
	close(start)
	wg.Wait()
	createWall := time.Since(tStart)
	log.Printf("creates returned in %s", createWall)

	var ids []string
	byStatus := map[string]int{}
	perHotel := map[string]map[string]int{}
	var cl, q, hm, ov []float64
	lastOK := 0.0
	for _, r := range res {
		k := strconv.Itoa(r.Status)
		if r.Err != "" && r.Status == 0 {
			k = "transport_error"
		}
		byStatus[k]++
		hh := r.Hotel
		if hh == "" {
			hh = "none"
		}
		if perHotel[hh] == nil {
			perHotel[hh] = map[string]int{}
		}
		perHotel[hh][k]++
		if r.Status == 202 && r.ID != "" {
			ids = append(ids, r.ID)
			cl, q, hm, ov = append(cl, r.ClientMs), append(q, r.QueueMs), append(hm, r.HotelMs), append(ov, r.OverheadMs)
			if r.DoneAtMs > lastOK {
				lastOK = r.DoneAtMs
			}
		}
	}
	_, brokerStats := stats(context.Background())

	// Phase 2: hold.
	phase.Store("hold")
	holdStart := time.Now()
	var hbOK, hbFail, exOK, exFail atomic.Int64
	pool := func(list []string, fn func(string)) {
		sem := make(chan struct{}, 64)
		var w sync.WaitGroup
		for _, id := range list {
			if ctx.Err() != nil {
				break
			}
			sem <- struct{}{}
			w.Add(1)
			go func(id string) { defer w.Done(); defer func() { <-sem }(); fn(id) }(id)
		}
		w.Wait()
	}
	hbTTL := *ttl
	heartbeat := func() {
		pool(ids, func(id string) {
			st, _, _, err := call(ctx, "POST", "/v1/sandboxes/"+id+"/heartbeat", map[string]any{"ttl_seconds": hbTTL})
			if err == nil && st == 200 {
				hbOK.Add(1)
			} else {
				hbFail.Add(1)
			}
		})
	}
	samp := ids[:min(*sample, len(ids))]
	var execMs []float64
	var emu sync.Mutex
	// Internet check: one HTTPS fetch from rooms spread over the whole run.
	var netOK, netFail atomic.Int64
	var netMs []float64
	netByHotel := map[string][2]int{}
	if *netCheck > 0 && len(ids) > 0 {
		step := max(1, len(ids)/(*netCheck))
		var pick []string
		for i := 0; i < len(ids) && len(pick) < *netCheck; i += step {
			pick = append(pick, ids[i])
		}
		pool(pick, func(id string) {
			st, _, out, err := call(ctx, "POST", "/v1/sandboxes/"+id+"/exec", map[string]any{"cmd": []string{"sh", "-c", "wget -q -T 15 -O /dev/null https://www.cloudflare.com/cdn-cgi/trace && echo net-ok"}, "timeout_seconds": 30})
			hotel, _, _ := strings.Cut(id, ".")
			var doc map[string]any
			_ = json.Unmarshal(out, &doc)
			ok := err == nil && st == 200 && strings.Contains(fmt.Sprint(doc["stdout"]), "net-ok")
			emu.Lock()
			c := netByHotel[hotel]
			if ok {
				c[0]++
				if d, isNum := doc["duration_ms"].(float64); isNum {
					netMs = append(netMs, d)
				}
			} else {
				c[1]++
			}
			netByHotel[hotel] = c
			emu.Unlock()
			if ok {
				netOK.Add(1)
			} else {
				netFail.Add(1)
			}
		})
	}
	lastHB := time.Now()
	nextExec := time.Now()
	for time.Since(holdStart) < *hold && ctx.Err() == nil {
		if time.Since(lastHB) >= *hbEvery {
			heartbeat()
			lastHB = time.Now()
		}
		if time.Now().After(nextExec) {
			pool(samp, func(id string) {
				t := time.Now()
				st, _, out, err := call(ctx, "POST", "/v1/sandboxes/"+id+"/exec", map[string]any{"cmd": []string{"sh", "-c", "echo ok; cat /proc/loadavg"}, "timeout_seconds": 20})
				if err == nil && st == 200 && bytes.Contains(out, []byte(`ok\n`)) {
					exOK.Add(1)
					emu.Lock()
					execMs = append(execMs, float64(time.Since(t).Microseconds())/1000)
					emu.Unlock()
				} else {
					exFail.Add(1)
				}
			})
			nextExec = time.Now().Add(*execEvery)
		}
		time.Sleep(time.Second)
	}
	// Final heartbeat so every room has the same TTL clock from here.
	if ctx.Err() == nil {
		if *finalTTL > 0 {
			hbTTL = *finalTTL
		}
		heartbeat()
	}
	hbStoppedS := time.Since(t0).Seconds()
	log.Printf("heartbeats stopped at t=%.0fs", hbStoppedS)

	// Phase 3: watch cleanup (or, after an abort, delete everything now).
	phase.Store("cleanup")
	firstZeroAPI := map[string]float64{}
	firstZeroCont := map[string]float64{}
	baseline := map[string]int{}
	if a := aborted.Load().(string); a != "" {
		log.Printf("ABORT: %s; deleting the run's rooms", a)
		_, _, _, _ = call(context.Background(), "DELETE", "/v1/sandboxes?label=run%3D"+run, nil)
	}
	watchStart := time.Now()
	for time.Since(watchStart) < *watch {
		hs, _ := stats(context.Background())
		done := len(hs) > 0
		for _, h := range hs {
			ts := time.Since(t0).Seconds()
			if h.APIRunning == 0 && h.APIDeleting == 0 {
				if _, ok := firstZeroAPI[h.ID]; !ok {
					firstZeroAPI[h.ID] = ts
				}
			} else {
				delete(firstZeroAPI, h.ID)
				done = false
			}
			if h.Containers <= baseline[h.ID] {
				if _, ok := firstZeroCont[h.ID]; !ok {
					firstZeroCont[h.ID] = ts
				}
			} else {
				delete(firstZeroCont, h.ID)
				done = false
			}
		}
		if done {
			break
		}
		time.Sleep(5 * time.Second)
	}
	pmu.Lock()
	defer pmu.Unlock()
	out := map[string]any{
		"run": run, "n": *n, "image": *image, "network": *network, "ttl_seconds": *ttl, "final_ttl_seconds": hbTTL, "aborted": aborted.Load(),
		"create_start_s": createStartS, "create_wall_s": createWall.Seconds(), "all_accepted_running_s": lastOK / 1000,
		"by_status": byStatus, "per_hotel": perHotel,
		"client_ms": pct(cl), "queue_ms": pct(q), "hotel_ms": pct(hm), "overhead_ms": pct(ov),
		"heartbeats_ok": hbOK.Load(), "heartbeats_failed": hbFail.Load(), "exec_ok": exOK.Load(), "exec_failed": exFail.Load(), "exec_ms": pct(execMs),
		"net_check_ok": netOK.Load(), "net_check_failed": netFail.Load(), "net_check_ms": pct(netMs), "net_check_by_hotel": netByHotel,
		"heartbeats_stopped_s": hbStoppedS, "api_empty_at_s": firstZeroAPI, "containers_gone_at_s": firstZeroCont,
		"peaks": peaks, "broker_stats_after_create": brokerStats,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	_ = os.WriteFile(filepath.Join(*outDir, "results.json"), b, 0o644)
	rb, _ := json.Marshal(res)
	_ = os.WriteFile(filepath.Join(*outDir, "creates.json"), rb, 0o644)
	fmt.Println(string(b))
}

var tStart time.Time
