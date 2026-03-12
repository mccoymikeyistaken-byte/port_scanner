# 🎉 Port Scanner (Fun Edition)

Welcome to the **Port Scanner** — your friendly neighborhood script that pokes TCP ports (gently) and tells you whether they are open or closed. 🚀

This project is a small Python script (`port_scanner.py`) built with `argparse`, so it behaves like a proper CLI tool and can scan a single port _or_ a full range.

---

## 🧠 What it does

- Scans a single port (e.g., `80`) and reports whether it is open or closed
- Scans a range of ports (e.g., `1-1024`) and reports each one, one-by-one
- Uses a timeout so it won’t hang forever (default is 0.5s per port)

---

## 🚀 How to run it

### Scan a single port

```bash
python port_scanner.py 127.0.0.1 80
```

### Scan a range of ports

```bash
python port_scanner.py 127.0.0.1 1-1024
```

### Get help (of course!)

```bash
python port_scanner.py -h
```

---

## 🧩 Notes

- This script is **not a security tool**, it’s a learning toy.
- Always scan hosts you have permission to scan.
- If you want to make it faster, try adding threading or async sockets (pull requests welcome!).

---

## 🤖 Why this exists

Because it’s fun to watch code automatically check network ports and tell you which ones are listening.

Plus this repo gives you a place to practice Python + `argparse` with a real-world style CLI.

---

Enjoy, and don’t forget to say hi to the open ports! 👋
