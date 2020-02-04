package icmp_tun

import "time"

type Stats struct {
	Loss100    uint32
	Count100   uint32
	Loss1000   uint32
	Count1000  uint32
	Loss10000  uint32
	Count10000 uint32
	// states
	bm        RingBitmap
	lastpktid uint32
	lastts    time.Time
}

func (st *Stats) Init() {
	st.bm.Init(kBitmapSize)
}

func (st *Stats) tail(length uint32) (loss uint32, count uint32) {
	s, c := st.bm.Count(st.bm.Last()-length+1, st.bm.Last())
	return c - s, c
}

const kPktidBreakThreshold = 1000

func (st *Stats) Update(pktid uint32) (updated bool) {
	if st.bm.Last()-pktid > kPktidBreakThreshold && pktid-st.bm.Last() > kPktidBreakThreshold {
		st.bm.Clear()
	}

	st.bm.Set(pktid)
	logdiff := st.bm.Last() - st.lastpktid
	now := time.Now()
	if logdiff < 100 || now.Sub(st.lastts) < 1*time.Second {
		// pass
		return false
	} else if st.lastpktid != 0 && 100 <= logdiff && logdiff < kBitmapSize/4 {
		st.Loss100, st.Count100 = st.tail(100)
		st.Loss1000, st.Count1000 = st.tail(1000)
		st.Loss10000, st.Count10000 = st.tail(10000)
		st.lastpktid = st.bm.Last()
		st.lastts = now
		return true
	} else {
		st.lastpktid = st.bm.Last()
		return false
	}
}
