import { Hero } from './components/Hero'
import { RecoverSecret } from './components/RecoverSecret'
import { ShareVault } from './components/ShareVault'
import { SiteHeader } from './components/SiteHeader'
import { SplitSecret } from './components/SplitSecret'
import { VaultProvider } from './hooks/useVault'
import './App.css'

export default function App() {
  return (
    <VaultProvider>
      <SiteHeader />
      <main>
        <Hero />
        <section className="workspace workspace--light" aria-label="Split and vault">
          <div className="workspace-inner">
            <SplitSecret />
            <ShareVault />
          </div>
        </section>
        <section className="workspace workspace--dark" aria-label="Recover">
          <div className="workspace-inner">
            <RecoverSecret />
          </div>
        </section>
      </main>
      <footer className="site-footer">
        <p>
          React frontend for the{' '}
          <a
            href="https://github.com/apeixinho/secretSharingFramework/tree/age/reactive-main-hardening-07a4"
            target="_blank"
            rel="noreferrer"
          >
            reactive Secret Sharing API
          </a>{' '}
          · shares persist locally in this browser
        </p>
      </footer>
    </VaultProvider>
  )
}
