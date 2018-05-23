const path = require('path')
const webpack = require('webpack')
const UglifyJsPlugin = require('uglifyjs-webpack-plugin')

module.exports = {
    entry: {
        mogrifyrequest: path.resolve(__dirname, 'django_fido/static/django_fido/js/u2f-registration.js')
    },
    output: {
        filename: '[name].js',
        path: path.resolve(__dirname, 'django_fido/static/django_fido/js'),
    },
    devtool: 'source-map',
    devServer: {
        contentBase: path.resolve(__dirname, 'django_fido/static/django_fido/js'),
    },
    module: {
        loaders: [{
            test: /\.js$/,
            include: path.join(__dirname, 'django_fido/static/django_fido/js'),
            exclude: /node_modules/,
            loaders: ['babel-loader'],
        }],
    },
    plugins: [
        new UglifyJsPlugin({
            sourceMap: true,
            uglifyOptions: { compress: { warnings: false } },
        }),
    ],
}
