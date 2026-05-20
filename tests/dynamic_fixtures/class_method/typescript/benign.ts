// Phase 19 (Track M.1) — class-method benign control for TypeScript.
import { execFileSync } from 'child_process';

export class UserService {
    constructor() {}
    run(input: string): string {
        return execFileSync('/bin/echo', [input]).toString();
    }
}
