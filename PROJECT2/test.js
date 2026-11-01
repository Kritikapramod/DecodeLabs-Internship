// Run with: node test.js   (Node is only needed for this optional test file, not for the app)
const { encryptText, decryptText, validateShift } = require("./script.js");
const cases = [
  ["Test 1", "HELLO WORLD", 3, "KHOOR ZRUOG"],
  ["Test 2", "abc", 1, "bcd"],
  ["Test 3", "XYZ", 3, "ABC"],
  ["Test 4", "Hello, World!", 3, "Khoor, Zruog!"],
  ["Test 5", "A", 25, "Z"],
  ["Test 7", "123 !?", 5, "123 !?"],
  ["Test 8", "Hello World, xyz XYZ!", 7, "Olssv Dvysk, efg EFG!"],
  ["Extra", "Line1\nLine 2\t(tab)", 13, "Yvar1\nYvar 2\t(gno)"],
];
let failed = 0;
for (const [name, input, shift, expected] of cases) {
  const actual = encryptText(input, shift), restored = decryptText(actual, shift);
  const ok = actual === expected && restored === input;
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${JSON.stringify(input)} +${shift} -> ${JSON.stringify(actual)} | decrypt -> ${JSON.stringify(restored)}`);
}
const bad = [0, 26, -3, 2.5, NaN].every(s => validateShift(s) !== "");
console.log(`${bad && validateShift(3) === "" ? "PASS" : "FAIL"} Shift validation`);
process.exit(failed || !bad ? 1 : 0);
