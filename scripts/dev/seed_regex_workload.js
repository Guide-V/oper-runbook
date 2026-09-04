// Seed workload producing a variety of $regex shapes in the mongod slow-query log.
const db2 = db.getSiblingDB("mongoops_test");
db2.customers.drop();
db2.customers.insertMany([
  { msisdn: "66812345678", name: "Somchai Jaidee", email: "somchai@example.com", tags: ["vip", "postpaid"] },
  { msisdn: "66898765432", name: "Suda Rakdee", email: "suda@example.org", tags: ["prepaid"] },
  { msisdn: "66911112222", name: "Anan Meesuk", email: "anan@example.net", tags: ["postpaid"] },
]);
db2.customers.createIndex({ msisdn: 1 });
db2.customers.createIndex({ name: 1 });

// log every operation as "slow"
db.getSiblingDB("admin").runCommand({ profile: 0, slowms: -1 });

// 1. explicit $regex operator with $options
db2.customers.find({ name: { $regex: "^som", $options: "i" } }).toArray();
// 2. BSON regex literal (prefix, case sensitive -> index friendly)
db2.customers.find({ msisdn: /^6681/ }).toArray();
// 3. unanchored, case-insensitive literal
db2.customers.find({ email: /example/i }).toArray();
// 4. $in with regex literals
db2.customers.find({ name: { $in: [/^Som/, /^Sud/] } }).toArray();
// 5. $not with regex
db2.customers.find({ name: { $not: /^Anan/ } }).toArray();
// 6. leading wildcard anti-pattern
db2.customers.find({ msisdn: /^.*2222$/ }).toArray();
// 7. aggregation $match + $regexMatch expression
db2.customers.aggregate([
  { $match: { email: { $regex: "\\.org$" } } },
  { $project: { name: 1, isVip: { $regexMatch: { input: "$name", regex: /^S/, options: "i" } } } },
]).toArray();
// 8. count with regex
db2.customers.countDocuments({ tags: /^post/ });
// 9. update with regex filter
db2.customers.updateMany({ email: /\.net$/ }, { $set: { flagged: true } });
// 10. delete with regex filter (matches nothing)
db2.customers.deleteMany({ name: /^ZZZ/ });
// 11. $expr with $regexFind
db2.customers.find({ $expr: { $ne: [{ $regexFind: { input: "$email", regex: "@(.*)\\." } }, null] } }).toArray();
// 12. no regex (control)
db2.customers.find({ msisdn: "66812345678" }).toArray();
// 13. getMore path: small batch so getMore is logged
const cur = db2.customers.find({ name: /a/ }).batchSize(1);
while (cur.hasNext()) cur.next();

// reset slowms to default
db.getSiblingDB("admin").runCommand({ profile: 0, slowms: 100 });

// dump slow query lines from the in-memory log
const log = db.getSiblingDB("admin").runCommand({ getLog: "global" }).log;
log.filter((l) => l.includes('"Slow query"') && l.includes("mongoops_test")).forEach((l) => print(l));
