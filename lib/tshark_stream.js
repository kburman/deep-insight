var spawn = require('child_process').spawn


function getTsharkLocation () {
	return 'tshark'
}

function createArgs (option) {
	var args = []

	if (option.filename) {
		args.push('-r' + option.filename)
	}

	if (option.decrypt) {
		args.push('-owlan.enable_decryption:TRUE')
	}

	if (option.wpa_pwd) {
		args.push('-ouat:80211_keys:\"wpa-pwd\",\"' + option.wpa_pwd + '\"')
	}

	if (option.oformat) {
		args.push('-T' + option.oformat)
	} else {
		args.push('-Tpdml')
	}

	if (option.enableNameResolution) {

	} else {
		args.push('-n')
	}

	if (option.count) {
		args.push('-n' + option.count)
	}

	args.push('-Rip')

	return args
}


function run_tshark (option) {
	var process_name = getTsharkLocation()
	var args = createArgs(option)
	return spawn(process_name, args)
}

module.exports = run_tshark