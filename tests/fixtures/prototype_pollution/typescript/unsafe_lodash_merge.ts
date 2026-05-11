// Unsafe: lodash `_.merge` invoked with attacker-controlled `req.body`.
import * as _ from 'lodash';

export function handler(req: any, res: any): void {
    const target: any = {};
    _.merge(target, req.body);
    res.json(target);
}
