const resultsDiv = document.getElementById('results');
const originalLog = console.log;
console.log = function (...args) {
    originalLog.apply(console, args);
    const p = document.createElement('p');
    p.textContent = args.join(' ');
    if (args[0] && args[0].includes('[FAIL]')) p.className = 'failed';
    if (args[0] && args[0].includes('Tests completed')) p.className = 'completed';
    resultsDiv.appendChild(p);
};

window.addEventListener('DOMContentLoaded', () => {
    if ((typeof window.PopTestFixtures !== 'undefined' || typeof window.FIXTURES !== 'undefined') && typeof window.runTests === 'function') {
        window.runTests().catch(console.error);
    } else {
        console.log("[ERROR] PopTestFixtures or runTests not loaded");
    }
});
