// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/cilium/checkmate"
)

type StoppableWaitGroupSuite struct{}

var _ = Suite(&StoppableWaitGroupSuite{})

func (s *SemaphoredMutexSuite) TestAdd(c *C) {
	l := NewStoppableWaitGroup()

	l.Add()
	c.Assert(l.i.Load(), Equals, int64(1))
	l.Add()
	c.Assert(l.i.Load(), Equals, int64(2))
	close(l.noopAdd)
	l.Add()
	c.Assert(l.i.Load(), Equals, int64(2))
}

func (s *SemaphoredMutexSuite) TestDone(c *C) {
	l := NewStoppableWaitGroup()

	l.i.Store(4)
	l.Done()
	c.Assert(l.i.Load(), Equals, int64(3))
	l.Done()
	c.Assert(l.i.Load(), Equals, int64(2))
	close(l.noopAdd)
	select {
	case _, ok := <-l.noopDone:
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(l.i.Load(), Equals, int64(1))
	select {
	case _, ok := <-l.noopDone:
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(l.i.Load(), Equals, int64(0))
	select {
	case _, ok := <-l.noopDone:
		c.Assert(ok, Equals, false)
	default:
		// channel should have been closed
		c.Assert(false, Equals, true)
	}

	l.Done()
	c.Assert(l.i.Load(), Equals, int64(0))
}

func (s *SemaphoredMutexSuite) TestStop(c *C) {
	l := NewStoppableWaitGroup()

	l.Add()
	c.Assert(l.i.Load(), Equals, int64(1))
	l.Add()
	c.Assert(l.i.Load(), Equals, int64(2))
	l.Stop()
	l.Add()
	c.Assert(l.i.Load(), Equals, int64(2))
}

func (s *SemaphoredMutexSuite) TestWait(c *C) {
	l := NewStoppableWaitGroup()

	waitClosed := make(chan struct{})
	go func() {
		l.Wait()
		close(waitClosed)
	}()

	l.Add()
	c.Assert(l.i.Load(), Equals, int64(1))
	l.Add()
	c.Assert(l.i.Load(), Equals, int64(2))
	l.Stop()
	l.Add()
	c.Assert(l.i.Load(), Equals, int64(2))

	l.Done()
	c.Assert(l.i.Load(), Equals, int64(1))
	select {
	case _, ok := <-waitClosed:
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(l.i.Load(), Equals, int64(0))
	select {
	case _, ok := <-waitClosed:
		// channel should have been closed
		c.Assert(ok, Equals, false)
	default:
	}

	l.Done()
	c.Assert(l.i.Load(), Equals, int64(0))
}

func (s *SemaphoredMutexSuite) TestWaitChannel(c *C) {
	l := NewStoppableWaitGroup()

	l.Add()
	c.Assert(l.i.Load(), Equals, int64(1))
	l.Add()
	c.Assert(l.i.Load(), Equals, int64(2))
	l.Stop()
	l.Add()
	c.Assert(l.i.Load(), Equals, int64(2))

	l.Done()
	c.Assert(l.i.Load(), Equals, int64(1))
	select {
	case _, ok := <-l.WaitChannel():
		// channel should not have been closed
		c.Assert(ok, Equals, true)
	default:
	}

	l.Done()
	c.Assert(l.i.Load(), Equals, int64(0))
	select {
	case _, ok := <-l.WaitChannel():
		// channel should have been closed
		c.Assert(ok, Equals, false)
	default:
	}

	l.Done()
	c.Assert(l.i.Load(), Equals, int64(0))
}

func (s *SemaphoredMutexSuite) TestParallelism(c *C) {
	l := NewStoppableWaitGroup()

	in := make(chan int)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case in <- rand.Intn(1 - 0):
			case <-stop:
				close(in)
				return
			}
		}
	}()
	var adds atomic.Int64
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			for a := range in {
				if a == 0 {
					adds.Add(1)
					l.Add()
				} else {
					l.Done()
					adds.Add(-1)
				}
			}
		}()
	}

	time.Sleep(time.Duration(rand.Intn(3-0)) * time.Second)
	close(stop)
	wg.Wait()
	for add := adds.Load(); add != 0; add = adds.Load() {
		switch {
		case add < 0:
			adds.Add(1)
			l.Add()
		case add > 0:
			l.Done()
			adds.Add(-1)
		}
	}
	l.Stop()
	l.Wait()
}
