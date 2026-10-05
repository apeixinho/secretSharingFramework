export function Hero() {
  return (
    <section className="hero" id="top" aria-labelledby="hero-brand">
      <div className="hero-atmosphere" aria-hidden="true">
        <svg className="shard-field" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice">
          <defs>
            <linearGradient id="shardFill" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#3d8b7a" stopOpacity="0.55" />
              <stop offset="100%" stopColor="#c9b07a" stopOpacity="0.25" />
            </linearGradient>
            <linearGradient id="lineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#9eb7ad" stopOpacity="0" />
              <stop offset="50%" stopColor="#9eb7ad" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#9eb7ad" stopOpacity="0" />
            </linearGradient>
          </defs>
          <g className="links" stroke="url(#lineGrad)" strokeWidth="1" fill="none">
            <path d="M180 170 L420 250 L610 160 L860 240 L1040 150" />
            <path d="M220 420 L470 360 L700 470 L930 390" />
            <path d="M300 620 L540 540 L780 650 L980 560" />
          </g>
          <g className="shards" fill="url(#shardFill)" stroke="#9eb7ad" strokeOpacity="0.28" strokeWidth="1">
            <polygon className="shard shard-a" points="180,150 230,170 210,230 155,210" />
            <polygon className="shard shard-b" points="420,230 480,210 510,270 445,295" />
            <polygon className="shard shard-c" points="610,140 670,165 645,225 585,205" />
            <polygon className="shard shard-d" points="860,220 920,200 945,260 880,285" />
            <polygon className="shard shard-e" points="1040,130 1090,155 1065,210 1010,185" />
            <polygon className="shard shard-f" points="470,340 530,320 555,385 490,405" />
            <polygon className="shard shard-g" points="700,450 760,430 785,500 715,520" />
            <polygon className="shard shard-h" points="540,520 600,500 625,570 555,590" />
            <polygon className="shard shard-i" points="930,370 990,350 1015,415 950,435" />
          </g>
        </svg>
      </div>

      <div className="hero-copy">
        <p className="eyebrow">Shamir threshold cryptography</p>
        <h1 id="hero-brand">Secret Sharing</h1>
        <p className="lede">
          Split a secret into signed shares. Reassemble it only when enough trusted fragments return.
        </p>
        <div className="cta-row">
          <a className="btn btn-primary" href="#split">
            Split a secret
          </a>
          <a className="btn btn-ghost" href="#recover">
            Recover from shares
          </a>
        </div>
      </div>
    </section>
  )
}
