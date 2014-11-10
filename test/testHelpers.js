/*jshint unused:false*/
function successfulPromise()
{
    'use strict';

    var theArguments = arguments;
    return {
        then: function (callback)
        {
            callback.apply(null, theArguments);
            return this;
        },
        catch: function ()
        {
            return this;
        },
        finally: function (callback)
        {
            callback.apply(null, theArguments);
            return this;
        }
    };
}
function unsuccessfulPromise()
{
    'use strict';

    var theArguments = arguments;
    return {
        then: function ()
        {
            return this;
        },
        catch: function (callback)
        {
            callback.apply(null, theArguments);
            return this;
        },
        finally: function (callback)
        {
            callback.apply(null, theArguments);
            return this;
        }
    };
}

function mockGettext(translation)
{
    'use strict';

    var gettextCatalog = jasmine.createSpyObj('gettextCatalog', ['getString', 'setCurrentLanguage']);
    gettextCatalog.getString.andCallFake(function (key)
    {
        return translation[key];
    });
    return gettextCatalog;
}
