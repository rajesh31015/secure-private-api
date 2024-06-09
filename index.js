const jwt = require("jsonwebtoken");

const createToken = async (request, expiresIn = 160, secretId) => {
    const formData = request.body;
    const api = request.originalUrl;
    const endpoint = request.get('origin');
    const iss = endpoint + api;
    const token = await jwt.sign({
        iss: iss,
        data: formData
    }, secretId, { expiresIn: expiresIn });
    return token;
};

const createCustomToken = async (data, expiresIn = 160, secretId) => {
    const formData = data.body;
    const iss = data.iss;
    const token = await jwt.sign({
        iss: iss,
        data: formData
    }, secretId, { expiresIn: expiresIn });
    return token;
};

const verifyToken = async (request,issData,secretId) => {
    let token = "";
    token = request.headers["x-auth-token"];
    if (token) {
        try {
            const tmpData = jwt.verify(token, secretId);
            if (issData.indexOf(tmpData.iss) !== -1) {
                return {
                    isVerified: true,
                    data: tmpData.data
                };
            } else {
                return {
                    isVerified: false
                };
            }
        } catch (err) {
            return {
                isVerified: false
            };
        }
    } else {
        return {
            isVerified: false
        };
    }
};

module.exports = {
    createToken,
    createCustomToken,
    verifyToken
};