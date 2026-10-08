const resultsDiv = document.getElementById('results');
const originalLog = console.log;
console.log = function(...args) {
    originalLog.apply(console, args);
    const p = document.createElement('p');
    p.textContent = args.join(' ');
    if (args[0] && args[0].includes('[FAIL]')) p.className = 'failed';
    if (args[0] && args[0].includes('Tests completed')) p.className = 'completed';
    resultsDiv.appendChild(p);
};

// Run tests (test.js executes automatically)
setTimeout(() => {
    if (typeof window.FIXTURES !== 'undefined') {
        runTests().catch(console.error);
    } else {
        console.log("[ERROR] FIXTURES not loaded");
    }
}, 100);
