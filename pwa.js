
(async () => {

    let configUrl = 'http://curisco.shop/renomear/pwa-config.json';

    try {
        let cfg = await fetch(configUrl).then(r => r.json());

        document.title = cfg.nome;

        let link = document.createElement('link');
        link.rel = 'manifest';
        link.href = 'manifest.json';
        document.head.appendChild(link);

        let meta = document.createElement('meta');
        meta.name = 'theme-color';
        meta.content = '#22c55e';
        document.head.appendChild(meta);

        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('service-worker.js');
        }

    } catch(e) {
        console.log('Erro ao carregar config');
    }

})();
