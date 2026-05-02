// Validated-flow propagation through helper chains
// (`SsaFuncSummary::validated_params_to_return`, CVE-2026-25544 deep
// fix).  `sanitize` validates its parameter via a regex allowlist
// and throws on failure; `buildQuery` interpolates the sanitised
// result into a SQL fragment; the handler hands the fragment to a
// raw-SQL execute callee.
//
// On a normal-returning call to either helper, the actual argument
// passed validation by construction, so `db.query(sql)` must not
// re-flag downstream taint findings.  The summary records
// `validated_params_to_return: [0]` on `sanitize` after the
// `regex.test` guard, propagates the bit through `buildQuery` via
// summary re-extraction, and the caller's sink therefore observes
// `all_validated = true`.
//
// Pinned by:
//   * tests/lib::validated_params_to_return_suppresses_one_hop_helper_validator
//   * tests/lib::validated_params_to_return_suppresses_two_hop_helper_validator

import express, { Request, Response } from 'express';

const SAFE_VALUE_REGEX = /^[\w@.\-+:]*$/;

const sanitize = (value: string): string => {
    if (!SAFE_VALUE_REGEX.test(value)) {
        throw new Error('value is not allowed');
    }
    return value;
};

const buildQuery = (column: string, value: string): string => {
    const safe = sanitize(value);
    return column + '=' + safe;
};

const app = express();
app.use(express.json());

app.post('/q', (req: Request, res: Response) => {
    const userValue = req.body.filter as string;
    const sql = buildQuery('data', userValue);
    res.send(sql);
});
