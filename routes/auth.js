const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { check } = require('express-validator');
const auth = require('../middleware/auth');

router.post('/',
	[
		check('email', 'Agrega un email valido.').isEmail(),
		check('password', 'El password no debe ir vacio').not().isEmpty()
	],
	authController.autenticarUsuario
);

router.get('/',
	auth,
	authController.usuarioAutenticado
);

module.exports = router;
