import express from 'express';

interface SafeInput {
    name: string;
    age: number;
}

var app = express();

app.post('/update', function(req: any, res: any) {
    // Type assertion does NOT sanitize
    var input = req.body as SafeInput;
    var query = 'UPDATE users SET name = \'' + input.name + '\' WHERE age = ' + input.age;
    // SQL injection despite type assertion
    res.send(query);
});
