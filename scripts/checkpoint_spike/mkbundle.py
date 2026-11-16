import json, os, sys
bundle, fill, mem_gib, netns = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
here = os.path.dirname(os.path.abspath(__file__))
os.makedirs(f"{bundle}/rootfs", exist_ok=True)
for d in ("usr", "lib", "lib64", "bin", "sbin", "etc", "work", "bench", "proc", "dev", "sys", "tmp"):
    os.makedirs(f"{bundle}/rootfs/{d}", exist_ok=True)
spec = json.load(open(f"{bundle}/config.json"))
spec["root"] = {"path": "rootfs", "readonly": True}
spec["process"]["terminal"] = False
spec["process"]["args"] = ["/usr/bin/python3", "-u", "/bench/workload.py", fill, "10.231.0.1" if netns != "none" else ""]
spec["process"]["cwd"] = "/work"
ro = ["rbind", "ro"]
for d in ("usr", "lib", "lib64", "bin", "sbin", "etc"):
    spec["mounts"].append({"destination": f"/{d}", "type": "bind", "source": f"/{d}", "options": ro})
spec["mounts"].append({"destination": "/bench", "type": "bind", "source": here, "options": ro})
spec["mounts"].append({"destination": "/work", "type": "bind", "source": f"{bundle}/work", "options": ["rbind", "rw"]})
os.makedirs(f"{bundle}/work", exist_ok=True)
ns = [n for n in spec["linux"]["namespaces"] if n["type"] != "network"]
if netns != "none":
    ns.append({"type": "network", "path": f"/var/run/netns/{netns}"})
else:
    ns.append({"type": "network"})
spec["linux"]["namespaces"] = ns
spec["linux"]["resources"] = {"memory": {"limit": mem_gib << 30}}
spec["linux"]["cgroupsPath"] = "/ckspike/" + os.path.basename(bundle)
json.dump(spec, open(f"{bundle}/config.json", "w"), indent=1)
