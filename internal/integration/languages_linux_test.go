//go:build linux

package integration

import (
	"strings"
	"sync"
	"testing"

	"github.com/Alkarim786/code-execution-sandbox/internal/judge"
	"github.com/Alkarim786/code-execution-sandbox/internal/service"
)

// Each language reads two integers and prints their sum.
var helloSum = map[string]string{
	"python":     "a, b = map(int, input().split())\nprint(a + b)\n",
	"c":          "#include <stdio.h>\nint main(){int a,b;scanf(\"%d %d\",&a,&b);printf(\"%d\\n\",a+b);return 0;}\n",
	"cpp":        "#include <iostream>\nint main(){int a,b;std::cin>>a>>b;std::cout<<a+b<<std::endl;}\n",
	"javascript": "const [a,b]=require('fs').readFileSync(0,'utf8').trim().split(' ').map(Number);console.log(a+b);\n",
	"java":       "import java.util.*;\npublic class Main{public static void main(String[] x){Scanner s=new Scanner(System.in);System.out.println(s.nextInt()+s.nextInt());}}\n",
}

func TestEveryLanguageProducesAC(t *testing.T) {
	for lang, src := range helloSum {
		t.Run(lang, func(t *testing.T) {
			resp := eval(t, lang, src, "20 22", "42", service.Limits{})
			if resp.Verdict != judge.AC {
				t.Fatalf("%s: %+v", lang, resp)
			}
			t.Logf("%-10s compile %4d ms | run wall %4d ms cpu %4d ms mem %6d KB", lang, resp.CompileMs,
				resp.Tests[0].WallMs, resp.Tests[0].CPUMs, resp.Tests[0].MemoryKB)
		})
	}
}

func TestWrongAnswerAndRuntimeErrorPerLanguage(t *testing.T) {
	wrong := map[string]string{
		"python": "print(1)", "c": "#include <stdio.h>\nint main(){puts(\"1\");}", "cpp": "#include <iostream>\nint main(){std::cout<<1;}",
		"javascript": "console.log(1)", "java": "public class Main{public static void main(String[] a){System.out.println(1);}}",
	}
	for lang, src := range wrong {
		if resp := eval(t, lang, src, "", "2", service.Limits{}); resp.Verdict != judge.WA {
			t.Errorf("%s wrong answer: %+v", lang, resp)
		}
	}
	crash := map[string]string{
		"python": "raise SystemExit(3)", "c": "int main(){return 3;}", "cpp": "int main(){return 3;}",
		"javascript": "process.exit(3)", "java": "public class Main{public static void main(String[] a){System.exit(3);}}",
	}
	for lang, src := range crash {
		if resp := eval(t, lang, src, "", "", service.Limits{}); resp.Verdict != judge.RE {
			t.Errorf("%s non-zero exit: %+v", lang, resp)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	for lang, src := range map[string]string{
		"c": "int main( {", "cpp": "int main() { undefined_fn(); }", "java": "public class Main { void }",
	} {
		resp := eval(t, lang, src, "", "", service.Limits{})
		if resp.Verdict != judge.CE || resp.CompileOutput == "" {
			t.Errorf("%s: want CE with compiler output, got %+v", lang, resp)
		}
	}
}

func TestThreadsWorkInRunProfile(t *testing.T) {
	c := `#include <pthread.h>
#include <stdio.h>
static int total = 0; static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static void* work(void* a){ for(int i=0;i<1000;i++){pthread_mutex_lock(&m); total++; pthread_mutex_unlock(&m);} return 0; }
int main(){ pthread_t t[4]; for(int i=0;i<4;i++) pthread_create(&t[i],0,work,0); for(int i=0;i<4;i++) pthread_join(t[i],0); printf("%d\n", total); }`
	// -pthread is not passed by the judge's gcc line, but glibc >= 2.34 has pthreads built in.
	if resp := eval(t, "c", c, "", "4000", service.Limits{}); resp.Verdict != judge.AC {
		t.Fatalf("%+v", resp)
	}
	js := "const {Worker,isMainThread}=require('worker_threads');if(isMainThread){new Worker(__filename);}else{console.log('ok')}"
	if resp := eval(t, "javascript", js, "", "", service.Limits{}); resp.Verdict != judge.AC && !strings.Contains(resp.Tests[0].Stdout, "ok") {
		t.Fatalf("worker threads: %+v", resp)
	}
}

func TestLargeOutputWithinCapIsAccepted(t *testing.T) {
	src := "import sys\nsys.stdout.write('x' * 500000 + '\\n')\n"
	if resp := eval(t, "python", src, "", strings.Repeat("x", 500000), service.Limits{}); resp.Verdict != judge.AC {
		t.Fatalf("%+v", resp.Tests)
	}
}

func TestConcurrentSubmissionsDoNotInterfere(t *testing.T) {
	setup(t)
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := i * 3
			resp := svc.Evaluate(t.Context(), &service.Request{Language: "python", Source: helloSum["python"],
				Tests: []service.Test{{Input: strings.Join([]string{itoa(a), "1"}, " "), Expected: itoa(a + 1)}}})
			if resp.Verdict != judge.AC {
				errs <- itoa(i) + ": " + string(resp.Verdict) + " " + resp.Error
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
