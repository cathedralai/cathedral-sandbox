import json, os, sys
p = sys.argv[1]; s = json.load(open(p))
caps = [l.split()[0] for l in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "caps.txt"))]
for k in ("bounding", "effective", "permitted"):
    s["process"]["capabilities"][k] = caps
s["process"]["capabilities"].pop("inheritable", None); s["process"]["capabilities"].pop("ambient", None)
s["process"]["args"] = ["/usr/bin/dockerd", "--iptables=false", "--ip6tables=false", "--bridge=none", "--storage-driver=vfs", "--config-file", "/bench/dj.json"]
s["process"]["env"].append("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
for d in ("/var", "/run", "/tmp"):
    s["mounts"].append({"destination": d, "type": "tmpfs", "source": "tmpfs", "options": ["rw"]})
s["mounts"].append({"destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup", "options": ["rw"]})
s["root"]["readonly"] = True
json.dump(s, open(p, "w"), indent=1)
