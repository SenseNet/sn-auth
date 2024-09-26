document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('form');

    if (form) {
        const redirectUrlInput = form.querySelector('input[name="RedirectUrl"]');
        const callbackUriInput = form.querySelector('input[name="CallbackUri"]');

        const currentUrl = new URL(window.location.href);
        const searchParams = currentUrl.searchParams;

        let shouldUpdateUrl = false;

        if (redirectUrlInput && !searchParams.has('RedirectUrl') && !searchParams.has('redirectUrl')) {
            searchParams.set('RedirectUrl', redirectUrlInput.value);
            shouldUpdateUrl = true;
        }

        if (callbackUriInput && !searchParams.has('CallbackUri') && !searchParams.has('callbackUri')) {
            searchParams.set('CallbackUri', callbackUriInput.value);
            shouldUpdateUrl = true;
        }

        if (shouldUpdateUrl) {
            const newUrl = currentUrl.origin + currentUrl.pathname + '?' + searchParams.toString();
            window.history.replaceState(null, '', newUrl);
        }
    }
});