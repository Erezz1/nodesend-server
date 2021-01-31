const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');

module.exports = (req, res, next) => {

	const authHeader = req.get('Authorization');

	if (authHeader) {
		// Obtener token
		const token = authHeader.split(' ')[1];

		// Comprobar el JWT
		try {
			const usuario = jwt.verify(token, process.env.SECTRETA);
			req.usuario = usuario;
		} catch (error) {
			console.log(error);
			console.log('JSON Web Token no valido');
		}
	}

	return next();
}
