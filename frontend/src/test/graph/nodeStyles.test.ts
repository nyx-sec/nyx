import { describe, it, expect } from 'vitest';
import { getNodeStyle, getEdgeStyle } from '@/graph/styles';

describe('getNodeStyle', () => {
  it('returns a style for Entry nodes', () => {
    const s = getNodeStyle('Entry');
    expect(s.fill).toBe('#1c5c38');
    expect(s.shape).toBe('double');
  });

  it('returns a style for Exit nodes', () => {
    const s = getNodeStyle('Exit');
    expect(s.shape).toBe('double');
  });

  it('returns a style for If nodes', () => {
    const s = getNodeStyle('If');
    expect(s.shape).toBe('rect');
    expect(s.textFill).toBe('#ffffff');
  });

  it('returns a style for Loop nodes', () => {
    const s = getNodeStyle('Loop');
    expect(s.shape).toBe('rect');
  });

  it('returns a style for Call nodes', () => {
    const s = getNodeStyle('Call');
    expect(s.shape).toBe('rect');
  });

  it('returns a terminal shape for Return nodes', () => {
    const s = getNodeStyle('Return');
    expect(s.shape).toBe('terminal');
  });

  it('returns the default style for unknown node types', () => {
    const s = getNodeStyle('Unknown');
    expect(s.fill).toContain('rgba');
    expect(s.shape).toBe('rect');
  });

  it('default style has correct text color', () => {
    const s = getNodeStyle('Stmt');
    expect(s.textFill).toBe('#ffffff');
  });

  it('returns a specialized style for recursive call graph nodes', () => {
    const s = getNodeStyle('Call', 'callgraph', { isRecursive: true });
    expect(s.fill).toBe('#5a5042');
  });
});

describe('getEdgeStyle', () => {
  it('returns green color for True edges', () => {
    const s = getEdgeStyle('True');
    expect(s.color).toBe('#1c5c38');
    expect(s.dash).toEqual([]);
  });

  it('returns red color for False edges', () => {
    const s = getEdgeStyle('False');
    expect(s.color).toBe('#9d2f25');
    expect(s.dash).toEqual([]);
  });

  it('returns dashed style for Back edges', () => {
    const s = getEdgeStyle('Back');
    expect(s.color).toBe('#6c6660');
    expect(s.dash).toEqual([7, 4]);
  });

  it('returns dashed style for Exception edges', () => {
    const s = getEdgeStyle('Exception');
    expect(s.dash).toEqual([3, 3]);
  });

  it('returns default style for Seq edges', () => {
    const s = getEdgeStyle('Seq');
    expect(s.color).toContain('rgba');
    expect(s.dash).toEqual([]);
  });

  it('returns default style for unknown edge types', () => {
    const s = getEdgeStyle('Whatever');
    expect(s.color).toContain('rgba');
  });

  it('returns neutral call graph edges', () => {
    const s = getEdgeStyle('Call', 'callgraph');
    expect(s.dash).toEqual([]);
  });
});
