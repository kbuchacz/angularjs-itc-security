/*global module*/
module.exports = function (grunt)
{
    'use strict';

    var jenkinsOptions = {
        reporter: 'checkstyle',
        reporterOutput: 'target/jshint.xml'
    };

    grunt.initConfig({
        jshint: {
            options: {
                jshintrc: true
            },
            common: ['src/!(vendor)/*.js', 'tests/!(vendor)/*.js'],
            commonJenkins: {
                options: jenkinsOptions,
                src: ['<%=jshint.common%>']
            }
        },
        concat: {
            basic: {
                files: {
                    'dist/angularjs-itc-security.js': ['src/**/*.js']
                }
            }
        }
    });
    grunt.loadNpmTasks('grunt-contrib-jshint');
    grunt.loadNpmTasks('grunt-contrib-concat');
};
