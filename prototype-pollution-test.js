// This demonstrates how prototype pollution works in JavaScript
console.log("=== Prototype Pollution Demonstration ===\n");

// Normal object creation
let normalObject = { theme: "dark" };
console.log("1. Normal object:", normalObject);
console.log("   isAdmin property:", normalObject.isAdmin); // undefined

// Polluted object - simulating what happens when malicious JSON is parsed
let maliciousJson = '{"theme": "dark", "__proto__": {"isAdmin": true, "polluted": "SUCCESS"}}';
let parsedObject = JSON.parse(maliciousJson);

console.log("\n2. Object after parsing malicious JSON:", parsedObject);
console.log("   isAdmin property:", parsedObject.isAdmin); // undefined (in this case)

// Now let's demonstrate how this affects other objects
let anotherObject = {};
console.log("\n3. Another object before prototype pollution:", anotherObject);
console.log("   isAdmin property:", anotherObject.isAdmin); // undefined

// In a real vulnerable app, after prototype pollution:
// anotherObject.isAdmin would be true
// This is because the __proto__ of the base Object was modified

// Creating a new object to show the pollution effect
function createObject() {
    return {};
}

let obj1 = createObject();
let obj2 = createObject();

console.log("\n4. Objects created after prototype pollution:");
console.log("   obj1.polluted:", obj1.polluted); // Would be "SUCCESS" if pollution worked
console.log("   obj2.polluted:", obj2.polluted); // Would be "SUCCESS" if pollution worked

console.log("\n=== Real-world Impact ===");
console.log("In a vulnerable application, this could allow attackers to:");
console.log("- Set 'isAdmin' property to true on all objects");
console.log("- Bypass access controls by modifying object prototypes");
console.log("- Manipulate application logic");
console.log("- Potentially escalate privileges");
console.log("- Cause application instability");