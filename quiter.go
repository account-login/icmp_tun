package icmp_tun

import "sync"

type Quiter struct {
	mu   sync.Mutex
	cond sync.Cond
	n    int
	quit bool
}

func (q *Quiter) Init() {
	if q.n != 0 {
		panic("q.n != 0")
	}
	q.cond.L = &q.mu
	q.quit = false
}

func (q *Quiter) Quit() {
	q.mu.Lock()
	q.quit = true
	q.mu.Unlock()
	q.cond.Broadcast()
}

func (q *Quiter) IsQuit() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.quit
}

func (q *Quiter) Wait() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for !(q.quit && q.n == 0) {
		q.cond.Wait()
	}
}

func (q *Quiter) Go(f func()) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.quit {
		return false
	}

	q.n++
	go func() {
		f()

		q.mu.Lock()
		q.n--
		n := q.n
		q.mu.Unlock()
		if n == 0 {
			q.cond.Broadcast()
		}
	}()
	return true
}
