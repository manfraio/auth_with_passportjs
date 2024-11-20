exports.ensureAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next()
    }

    res.status(401).json({ error: 'You must be authenticated to access this resource' })
}