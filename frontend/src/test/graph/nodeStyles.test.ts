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

  it('returns a double shape for surface entry-point nodes', () => {
    const s = getNodeStyle('EntryPoint', 'surface');
    expect(s.shape).toBe('double');
    expect(s.fill).toBe('#1c5c38');
  });

  it('returns a terminal shape for surface dangerous-local nodes', () => {
    const s = getNodeStyle('DangerousLocal', 'surface');
    expect(s.shape).toBe('terminal');
    expect(s.fill).toBe('#9d2f25');
  });

  it('returns a warning fill for surface data-store nodes', () => {
    const s = getNodeStyle('DataStore', 'surface');
    expect(s.fill).toBe('#8c6310');
    expect(s.shape).toBe('rect');
  });

  it('returns an accent fill for surface external-service nodes', () => {
    const s = getNodeStyle('ExternalService', 'surface');
    expect(s.fill).toBe('#0b3d2a');
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

  it('returns a dashed style for surface auth_required_on edges', () => {
    const s = getEdgeStyle('auth_required_on', 'surface');
    expect(s.dash).toEqual([2, 4]);
  });

  it('returns a solid danger color for surface reaches edges', () => {
    const s = getEdgeStyle('reaches', 'surface');
    expect(s.color).toBe('#9d2f25');
    expect(s.dash).toEqual([]);
  });

  it('returns a dashed success style for surface triggers edges', () => {
    const s = getEdgeStyle('triggers', 'surface');
    expect(s.dash).toEqual([4, 3]);
  });

  it('returns a fallback style for unknown surface edge kinds', () => {
    const s = getEdgeStyle('mystery', 'surface');
    expect(s.color).toContain('rgba');
    expect(s.dash).toEqual([]);
  });
});
