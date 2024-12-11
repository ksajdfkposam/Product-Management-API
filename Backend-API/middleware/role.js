// middleware/role.js
const roleMiddleware = (allowedRoles) => {
    return (req, res, next) => {
        const userRole = req.user.role;

        if (!allowedRoles.includes(userRole)) {
            return res.status(403).json({ message: 'Access forbidden: insufficient permissions' });
        }

        next();
    };
};

module.exports = roleMiddleware;