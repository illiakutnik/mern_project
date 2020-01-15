const express = require('express')
const router = express.Router()
const auth = require('../../middleware/auth')
const { check, validationResult } = require('express-validator')

const Profile = require('../../models/Profile')
const User = require('../../models/User')

router.get('/me', auth, async (req, res) => {
	try {
		const profile = await Profile.findOne({
			user: req.user.id
		}).populate('user', ['name', 'avatar'])
		if (!profile) {
			return res.status(400).json({ msg: 'There is no profile for this user' })
		}
	} catch (err) {
		console.error(err.message)
		res.status(500).send('Server Error')
	}
})

router.post(
	'/',
	[
		auth,
		[
			check('status', 'Status is required')
				.not()
				.isEmpty(),
			check('skills', 'Skills is require')
				.not()
				.isEmpty()
		]
	],
	async (req, res) => {
		const {
			company,
			website,
			location,
			bio,
			status,
			githubusername,
			twitter,
			facebook,
			linkedin
		} = req.body
		const errors = validationResult(req)
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() })
		}
		const profileFields = {}
		profileFields.user = req.user.id
		if (company) profileFields.company = company
		if (website) profileFields.website = website
		if (location) profileFields.location = location
		if (bio) profileFields.bio = bio
		if (status) profileFields.status = status
		if (githubusername) profileFields.githubusername = githubusername

		if (typeof req.body.skills !== 'undefined') {
			profileFields.skills = req.body.skills
				.split(',')
				.map(skill => skill.trim())
		}

		profileFields.social = {}
		if (twitter) profileFields.social.twitter = twitter
		if (facebook) profileFields.social.facebook = facebook
		if (linkedin) profileFields.social.linkedin = linkedin

		try {
			let profile = Profile.findOne({ user: req.user.id })
			if (!profile) {
				profile = await Profile.findOneAndUpdate(
					{ user: req.user.id },
					{ $set: profileFields },
					{ new: true }
				)
				return res.json(profile)
			}
			profile = new Profile(profileFields)
			await profile.save()
			res.json(profile)
		} catch (err) {
			console.error(err.message)
			res.status(500).send('Server Error')
		}
	}
)

module.exports = router