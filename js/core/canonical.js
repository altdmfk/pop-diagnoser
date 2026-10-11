(function (root, factory) {
    const mod = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopCore = Object.assign(root.PopCore || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function () {
    const DEFAULT_FIELDS = ['method', 'host', 'path', 'query', 'bodyHash', 'nonce', 'timestamp'];

    function buildString(req, profile) {
        const fields = (profile && Array.isArray(profile.canonicalFields))
            ? profile.canonicalFields
            : DEFAULT_FIELDS;
        const delimiter = req.delimiter !== undefined
            ? req.delimiter
            : ((profile && profile.delimiter) || '\n');
        let str = fields.map(f => req[f]).join(delimiter);
        if (req.trailingNewline) {
            str += delimiter;
        }
        return str;
    }

    return { buildString };
});
