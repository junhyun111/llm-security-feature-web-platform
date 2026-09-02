import {
  ArrowRight,
  CheckCircle2,
  Code2,
  FileSearch,
  ShieldCheck,
  Sparkles,
  WandSparkles
} from 'lucide-react'
import { Link, Navigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import './LandingPage.css'

export default function LandingPage() {
  const { user, loading } = useAuth()
  if (!loading && user) return <Navigate to="/library" replace />

  return (
    <div className="landing-page">
      <header className="landing-nav">
        <Link to="/" className="landing-brand"><span className="landing-brand-mark"><ShieldCheck size={19} /></span><strong>LLM Security</strong></Link>
        <nav><a href="#how-it-works">How it works</a><a href="#capabilities">Capabilities</a></nav>
        <div className="landing-nav-actions"><Link className="landing-login" to="/login">Log in</Link><Link className="primary-button compact" to="/register">Get started <ArrowRight size={14} /></Link></div>
      </header>

      <main>
        <section className="landing-hero">
          <div className="landing-hero-copy"><span className="landing-kicker"><Sparkles size={14} /> AI-assisted code security</span><h1>Find the flaw.<br /><em>Fix it with confidence.</em></h1><p>Evidence-grounded vulnerability analysis for C and C++ projects. Discover what is at risk, understand why it matters, and generate a verified patch from one workspace.</p><div className="landing-hero-actions"><Link className="primary-button" to="/register">Start your first analysis <ArrowRight size={16} /></Link><a className="landing-text-link" href="#how-it-works">See how it works <ArrowRight size={14} /></a></div><div className="landing-trust"><CheckCircle2 size={15} /> Multi-expert validation <span /> <CheckCircle2 size={15} /> Safe patch preview</div></div>
          <div className="landing-hero-visual" aria-label="Security finding preview"><div className="preview-window"><div className="preview-window-bar"><span /><span /><span /><b>Analysis report</b><small>Completed</small></div><div className="preview-body"><div className="preview-sidebar"><strong>Findings</strong><span className="preview-count">7</span><div className="preview-item active"><i className="dot green" /><span><b>CWE-190</b><small>Integer Overflow</small></span></div><div className="preview-item"><i className="dot green" /><span><b>CWE-416</b><small>Use After Free</small></span></div><div className="preview-item"><i className="dot amber" /><span><b>CWE-369</b><small>Divide by Zero</small></span></div></div><div className="preview-detail"><div className="preview-detail-top"><span className="preview-label">CWE-190 · Integer Overflow</span><span className="preview-status">● Validated</span></div><h3>Integer calculation may wrap before allocation</h3><code>imgRead.c · ProcessImage · Line 46</code><div className="preview-section"><small>ROOT CAUSE</small><p>Width and height are added without an overflow guard before the buffer allocation.</p></div><div className="preview-code"><span>46</span><b>int size1 = img-&gt;width + img-&gt;height;</b></div><div className="preview-buttons"><span>View in code</span><strong>Generate patch <WandSparkles size={12} /></strong></div></div></div></div></div>
        </section>

        <section className="landing-proof"><p>Built for teams who need more than a noisy scanner</p><div><span>Source-level evidence</span><span>Independent validation</span><span>Reproducible review</span><span>Verified changes</span></div></section>

        <section className="landing-section" id="how-it-works"><div className="landing-section-heading"><span className="landing-kicker">HOW IT WORKS</span><h2>From source code to a<br />defensible fix.</h2><p>Every result is organized around the decision you need to make next.</p></div><div className="landing-steps"><article><span>01</span><FileSearch size={21} /><h3>Scan your project</h3><p>Upload a C or C++ project and let the analysis engine map its risky code paths.</p></article><article><span>02</span><ShieldCheck size={21} /><h3>Validate the finding</h3><p>Independent expert perspectives check the evidence so you can focus on real issues.</p></article><article><span>03</span><WandSparkles size={21} /><h3>Review the fix</h3><p>Generate a patch, inspect the original and proposed code, then approve with context.</p></article></div></section>

        <section className="landing-section landing-capabilities" id="capabilities"><div className="landing-section-heading"><span className="landing-kicker">ONE CLEAR WORKSPACE</span><h2>Security work, without<br />the guesswork.</h2></div><div className="landing-capability-grid"><article><Code2 size={20} /><h3>Code-level context</h3><p>Jump from a finding directly to the exact file, function, and line that needs attention.</p></article><article><ShieldCheck size={20} /><h3>Evidence you can explain</h3><p>See root cause, impact, validation, and technical evidence in a readable review flow.</p></article><article><WandSparkles size={20} /><h3>Patch with guardrails</h3><p>Preview changes in an isolated workspace before anything is approved.</p></article></div></section>

        <section className="landing-cta"><div><span className="landing-kicker">READY WHEN YOU ARE</span><h2>Make your next code review<br />a security review, too.</h2></div><Link className="primary-button" to="/register">Create your library <ArrowRight size={16} /></Link></section>
      </main>
      <footer className="landing-footer"><span>© 2026 LLM Security</span><span>Evidence first. Safer by design.</span></footer>
    </div>
  )
}
