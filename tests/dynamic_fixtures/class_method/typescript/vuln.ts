// Phase 19 (Track M.1) — class-method vuln fixture for TypeScript.
//
// UserService.run forwards user input directly to a shell.  Default ctor.
import { execSync } from 'child_process';

export class UserService {
    constructor() {}
    run(input: string): string {
        // SINK: untrusted input flows into the shell
        return execSync('echo ' + input).toString();
    }
}
