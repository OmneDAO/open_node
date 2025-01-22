// executor.js

const vm = require('vm');
const fs = require('fs');

const [,, contractPath, functionName, argsJson] = process.argv;

try {
    // Read and compile the contract code
    const code = fs.readFileSync(contractPath, 'utf-8');
    const contract = require(contractPath);

    // Parse arguments
    const args = JSON.parse(argsJson);

    if (typeof contract[functionName] !== 'function') {
        console.error(`Function ${functionName} not found in contract.`);
        process.exit(1);
    }

    // Execute the function in a sandboxed environment
    const sandbox = {
        console: {
            log: (msg) => console.log(msg),
            error: (msg) => console.error(msg)
        },
        require,
        module,
        exports
    };
    vm.createContext(sandbox);

    const result = contract[functionName](...args);
    
    // Ensure the result is a string for consistent handling
    if (typeof result === 'object') {
        console.log(JSON.stringify(result));
    } else {
        console.log(result.toString());
    }

} catch (error) {
    console.error(`Error executing contract function: ${error.message}`);
    process.exit(1);
}
