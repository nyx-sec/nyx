// go-safe-realrepo-017 — distilled from prometheus
// `cmd/promtool/tsdb.go::startProfiling` (lines 230, 239, 246, 252):
// 4 findings on the same function plus widespread similar shapes
// across the prometheus tree.  Pattern:
//
//     b.cpuprof, err = os.Create(...)
//
// The resource is owned by the struct `*writeBenchmark`.  Closure
// happens in a paired method `stopProfiling()`.  The current function
// body cannot observe that closure, so any per-body resource analysis
// fires unconditionally.
//
// Engine fix (depth: structural — both layers):
//   * src/state/transfer.rs::apply_call gates the acquire branch on
//     `!define_is_field_lhs` so member-expression LHS doesn't seed
//     `state.resource` in the dataflow lattice.
//   * src/cfg_analysis/resources.rs::run gates the structural rule's
//     acquire-iteration on the same `defines.contains('.')` check.

package safe

import (
	"os"
	"runtime/pprof"
)

type writeBenchmark struct {
	cpuprof   *os.File
	memprof   *os.File
	blockprof *os.File
	mtxprof   *os.File
	outPath   string
}

func (b *writeBenchmark) startProfiling() error {
	var err error
	b.cpuprof, err = os.Create(b.outPath + "/cpu.prof")
	if err != nil {
		return err
	}
	if err := pprof.StartCPUProfile(b.cpuprof); err != nil {
		return err
	}
	b.memprof, err = os.Create(b.outPath + "/mem.prof")
	if err != nil {
		return err
	}
	b.blockprof, err = os.Create(b.outPath + "/block.prof")
	if err != nil {
		return err
	}
	b.mtxprof, err = os.Create(b.outPath + "/mutex.prof")
	if err != nil {
		return err
	}
	return nil
}

func (b *writeBenchmark) stopProfiling() error {
	if b.cpuprof != nil {
		pprof.StopCPUProfile()
		b.cpuprof.Close()
		b.cpuprof = nil
	}
	if b.memprof != nil {
		b.memprof.Close()
		b.memprof = nil
	}
	if b.blockprof != nil {
		b.blockprof.Close()
		b.blockprof = nil
	}
	if b.mtxprof != nil {
		b.mtxprof.Close()
		b.mtxprof = nil
	}
	return nil
}
