// Safe: lodash `_.merge` invoked with a constant-source object.
import * as _ from 'lodash';

export function build(): any {
    const target: any = {};
    _.merge(target, { a: 1, b: 2 });
    return target;
}
