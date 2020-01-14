const express = require('express')
const router = express.Router()
const gravatar = require('gravatar')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const { check, validationResult } = require('express-validator')

const User = require('../../models/User')

router.post(
	'/',
	[
		check('name', 'Name is required')
			.not()
			.isEmpty(),
		check('email', 'Type valid email').isEmail(),
		check('password', 'Password should be at least 5 characters').isLength({
			min: 5
		})
	],
	async (req, res) => {
		const err = validationResult(req)
		if (!err.isEmpty()) {
			return res.status(400).json({ errors: err.array() })
		}

		const { name, email, password } = req.body

		try {
			let user = await User.findOne({ email })
			if (user) {
				return res
					.status(400)
					.json({ errors: [{ message: 'User already exist' }] })
			}

			const avatar = gravatar.url(email, {
				s: '200',
				r: 'pg',
				d: 'mm'
			})

			user = new User({
				name,
				email,
				password,
				avatar
			})

			const salt = await bcrypt.genSalt(10)
			user.password = await bcrypt.hash(password, salt)

			await user.save()

			const payload = {
				user: {
					id: user.id
				}
			}
			jwt.sign(
				payload,
				config.get('secret'),
				{ expiresIn: 360000 },
				(err, token) => {
					if (err) throw err
					res.json({ token })
				}
			)
		} catch (err) {
			console.error(err.message)
			res.status(500).send('Server error')
		}
	}
)

module.exports = router
