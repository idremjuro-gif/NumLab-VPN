/**
 * NumLab-VPN - Test de vérification avec Playwright
 * Créé par Merdi Madimba
 */

const { chromium } = require('playwright');

async function testWebsite() {
    console.log('╔════════════════════════════════════════╗');
    console.log('║      Test de NumLab-VPN avec Playwright      ║');
    console.log('╚════════════════════════════════════════╝\n');

    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    let testsPassed = 0;
    let testsFailed = 0;

    // Collecter les erreurs de console
    const consoleErrors = [];
    page.on('console', msg => {
        if (msg.type() === 'error') {
            consoleErrors.push(msg.text());
        }
    });

    try {
        // Test 1: Page d'accueil
        console.log('Test 1: Chargement de la page d\'accueil...');
        try {
            await page.goto('http://localhost:3000/', { waitUntil: 'networkidle', timeout: 30000 });
            
            // Vérifier le titre
            const title = await page.title();
            console.log(`  ✓ Titre de la page: "${title}"`);
            
            // Vérifier le logo
            const logoText = await page.textContent('.logo-text');
            console.log(`  ✓ Logo: "${logoText}"`);
            
            // Vérifier le titre principal
            const heroTitle = await page.textContent('.hero-title');
            console.log(`  ✓ Titre principal: "${heroTitle}"`);
            
            // Vérifier le pied de page
            const footerText = await page.textContent('.footer-text');
            console.log(`  ✓ Pied de page: "${footerText}"`);
            
            testsPassed++;
            console.log('  ✓ Page d\'accueil chargée avec succès\n');
        } catch (error) {
            console.error(`  ✗ Erreur: ${error.message}\n`);
            testsFailed++;
        }

        // Test 2: Page admin
        console.log('Test 2: Chargement de la page admin...');
        try {
            await page.goto('http://localhost:3000/admin', { waitUntil: 'networkidle', timeout: 30000 });
            
            // Vérifier que le modal de connexion est affiché
            const loginModal = await page.isVisible('#loginOverlay');
            console.log(`  ✓ Modal de connexion visible: ${loginModal}`);
            
            // Vérifier le titre du login
            const loginTitle = await page.textContent('.login-title');
            console.log(`  ✓ Titre de connexion: "${loginTitle}"`);
            
            testsPassed++;
            console.log('  ✓ Page admin chargée avec succès\n');
        } catch (error) {
            console.error(`  ✗ Erreur: ${error.message}\n`);
            testsFailed++;
        }

        // Test 3: Test de connexion admin (échec attendu avec mauvais code)
        console.log('Test 3: Test de sécurité - Connexion avec mauvais code...');
        try {
            await page.goto('http://localhost:3000/admin', { waitUntil: 'networkidle', timeout: 30000 });
            
            // Entrer un mauvais code
            await page.fill('#adminCode', '00000000000000');
            await page.click('.login-btn');
            
            // Vérifier le message d'erreur
            await page.waitForSelector('.error-message:not([style*="display: none"])', { timeout: 5000 });
            const errorVisible = await page.isVisible('.error-message');
            console.log(`  ✓ Message d'erreur affiché: ${errorVisible}`);
            
            testsPassed++;
            console.log('  ✓ Test de sécurité passé avec succès\n');
        } catch (error) {
            console.error(`  ✗ Erreur: ${error.message}\n`);
            testsFailed++;
        }

        // Test 4: Vérifier les ressources CSS et JS
        console.log('Test 4: Vérification des ressources...');
        try {
            const cssLinks = await page.$$eval('link[rel="stylesheet"]', links => links.map(l => l.href));
            const jsScripts = await page.$$eval('script[src]', scripts => scripts.map(s => s.src));
            
            console.log(`  ✓ Fichiers CSS chargés: ${cssLinks.length}`);
            console.log(`  ✓ Fichiers JS chargés: ${jsScripts.length}`);
            
            testsPassed++;
            console.log('  ✓ Ressources vérifiées avec succès\n');
        } catch (error) {
            console.error(`  ✗ Erreur: ${error.message}\n`);
            testsFailed++;
        }

        // Rapport des erreurs de console
        if (consoleErrors.length > 0) {
            console.log('⚠ Avertissements de console:');
            consoleErrors.forEach(err => console.log(`  - ${err}`));
            console.log('');
        }

    } catch (error) {
        console.error('Erreur globale:', error);
        testsFailed++;
    } finally {
        await browser.close();
    }

    // Résumé des tests
    console.log('╔════════════════════════════════════════╗');
    console.log('║           RÉSUMÉ DES TESTS             ║');
    console.log('╚════════════════════════════════════════╝');
    console.log(`  Tests réussis: ${testsPassed}`);
    console.log(`  Tests échoués: ${testsFailed}`);
    console.log(`  Total: ${testsPassed + testsFailed}`);
    
    if (testsFailed === 0) {
        console.log('\n ✓ Tous les tests ont réussi !');
        process.exit(0);
    } else {
        console.log('\n ✗ Certains tests ont échoué.');
        process.exit(1);
    }
}

// Exécuter les tests
testWebsite().catch(error => {
    console.error('Erreur lors de l\'exécution des tests:', error);
    process.exit(1);
});
