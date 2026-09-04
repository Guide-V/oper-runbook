// Regex workload for a real Atlas (M10+) cluster so Performance Advisor records slow queries.
//
// Unlike seed_regex_workload.js (atlas-local) we cannot force slowms; Atlas picks the slow-op
// threshold from the cluster's average op time (~100 ms on an idle cluster). So we load enough
// documents that unanchored / case-insensitive regexes genuinely take longer than that.
//
//   mongosh "<connection string>/mongoops_test" --file scripts/dev/seed_regex_workload_atlas.js
//
// Afterwards (allow a few minutes for Performance Advisor ingestion):
//   mongoops regex-finder atlas -c <cluster> --since 1h -n mongoops_test.customers

const TOTAL = Number(process.env.MONGOOPS_SEED_DOCS || 300000);
const BATCH = 10000;
const REPEAT = 3;

const coll = db.getSiblingDB("mongoops_test").customers;
coll.drop();

const domains = ["example.com", "example.org", "example.net", "example.co.th"];
const first = ["Somchai", "Suda", "Anan", "Kanya", "Prasert", "Malee", "Wichai", "Nok"];
const last = ["Jaidee", "Rakdee", "Meesuk", "Srisuk", "Thongdee", "Boonmee"];

for (let start = 0; start < TOTAL; start += BATCH) {
  const docs = [];
  for (let i = start; i < Math.min(start + BATCH, TOTAL); i++) {
    docs.push({
      msisdn: "668" + String(i).padStart(8, "0"),
      name: first[i % first.length] + " " + last[i % last.length] + " " + i,
      email: "user" + i + "@" + domains[i % domains.length],
      tags: [i % 2 ? "postpaid" : "prepaid", i % 7 ? "std" : "vip"],
      note: "customer record " + i,
    });
  }
  coll.insertMany(docs, { ordered: false });
  print(`inserted ${Math.min(start + BATCH, TOTAL)}/${TOTAL}`);
}
coll.createIndex({ msisdn: 1 });
coll.createIndex({ name: 1 });
coll.createIndex({ email: 1 });

const workload = [
  ["find $regex + $options i", () => coll.find({ name: { $regex: "^som", $options: "i" } }).limit(5).toArray()],
  ["find prefix literal (control, fast)", () => coll.find({ msisdn: /^66800001/ }).toArray()],
  ["find unanchored case-insensitive", () => coll.find({ email: /example\.org$/i }).limit(5).toArray()],
  ["find $in regex", () => coll.find({ name: { $in: [/Rakdee 1234/, /Meesuk 5678/] } }).toArray()],
  ["find $not regex", () => coll.countDocuments({ name: { $not: /^S/ } })],
  ["find leading wildcard", () => coll.find({ msisdn: /^.*99999$/ }).toArray()],
  ["aggregate $match + $regexMatch", () =>
    coll.aggregate([
      { $match: { email: { $regex: "@example\\.co\\.th$" } } },
      { $project: { name: 1, isS: { $regexMatch: { input: "$name", regex: /^S/, options: "i" } } } },
      { $limit: 5 },
    ]).toArray()],
  ["find $expr $regexFind", () =>
    coll.find({ $expr: { $ne: [{ $regexFind: { input: "$note", regex: "record 12345$" } }, null] } }).toArray()],
  ["update with regex filter", () => coll.updateMany({ email: /user1234\d@example\.net$/ }, { $set: { flagged: true } })],
  ["find no regex (control)", () => coll.find({ msisdn: "66800000001" }).toArray()],
];

for (let r = 0; r < REPEAT; r++) {
  for (const [label, run] of workload) {
    const t0 = Date.now();
    run();
    print(`${label}: ${Date.now() - t0} ms`);
  }
}
