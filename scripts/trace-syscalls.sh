#!/bin/sh
# Dev tool: list syscalls used by each runtime that are NOT in the sandbox allowlist.
# Usage (inside the test container): scripts/trace-syscalls.sh
set -e
ALLOWED=$(grep -oE '(a|Name:) ?\(?"[a-z0-9_]+"' internal/sandbox/policy_linux_amd64.go | grep -oE '"[a-z0-9_]+"' | tr -d '"' | sort -u)
mkdir -p /tmp/tr && cd /tmp/tr
cat > hello.js <<'JS'
const {Worker,isMainThread}=require('worker_threads');
if(isMainThread){const w=new Worker(__filename);w.on('exit',()=>console.log(require('fs').readFileSync(0,'utf8').trim()));}
JS
cat > Main.java <<'JAVA'
import java.util.*;
public class Main{public static void main(String[] x) throws Exception{
 Scanner s=new Scanner(System.in); System.out.println(s.nextInt()+s.nextInt());
 Thread t=new Thread(()->System.out.println("thread")); t.start(); t.join();
 List<Integer> l=new ArrayList<>(); for(int i=0;i<200000;i++) l.add(i); System.gc();}}
JAVA
trace() { name=$1; shift; echo "5 6" | strace -f -qq -o "$name.txt" "$@" >/dev/null 2>&1 || true
  sed -E 's/^[0-9]+ +//' "$name.txt" | grep -oE '^[a-z_0-9]+\(' | tr -d '(' | sort -u > "$name.sys"; }
trace node node hello.js
trace javac javac -J-Xmx256m -J-XX:+UseSerialGC -d /tmp/tr Main.java
trace java java -Xmx64m -Xss8m -XX:+UseSerialGC -XX:TieredStopAtLevel=1 -XX:-UsePerfData -Xshare:auto -cp /tmp/tr Main
trace py python3 -S -E -c "import threading,sys,time;print(1)"
for n in node javac java py; do
  echo "== $n: not in allowlist:"; echo "$ALLOWED" > allowed.txt
  comm -23 $n.sys allowed.txt | tr '\n' ' '; echo
done
