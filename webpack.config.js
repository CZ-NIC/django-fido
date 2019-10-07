const path = require('path')

module.exports = {
    entry: {
        fido2: [
            'babel-polyfill',
            path.resolve(__dirname, 'django_fido/js/fido2.js'),
        ],
    },
    output: {
        path: path.join(__dirname, 'django_fido/static/django_fido/js'),
        library: '[name]',
        filename: '[name].js',
        sourceMapFilename: '[name].js.map',
    },
    devtool: 'source-map',
    module: {
        rules: [{
            test: /\.js$/,
            include: path.join(__dirname, 'django_fido/js'),
            exclude: /node_modules/,
            use: ['babel-loader'],
        }],
    },
}
