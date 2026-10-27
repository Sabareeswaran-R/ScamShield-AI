
import { useState } from 'react'
import './App.css'

const API_URL = 'http://127.0.0.1:8000'

function App() {
  const [message, setMessage] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const [activePage, setActivePage] = useState('scanner')
  const [history, setHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [historyError, setHistoryError] = useState('')
  const [historyFilter, setHistoryFilter] = useState('all')
  const [selectedRecord, setSelectedRecord] = useState(null)

  const loadHistory = async () => {
    setHistoryLoading(true)
    setHistoryError('')

    try {
      const response = await fetch(`${API_URL}/api/history`)
      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          typeof data.detail === 'string'
            ? data.detail
            : 'Unable to load analysis history.',
        )
      }

      setHistory(Array.isArray(data.history) ? data.history : [])
    } catch (err) {
      setHistoryError(
        err.message || 'Could not connect to the history API.',
      )
    } finally {
      setHistoryLoading(false)
    }
  }

  const analyzeMessage = async (event) => {
    event.preventDefault()

    if (!message.trim()) {
      setError('Please enter a message to analyze.')
      setResult(null)
      return
    }

    setLoading(true)
    setError('')
    setResult(null)

    try {
      const response = await fetch(`${API_URL}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: message.trim(),
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          typeof data.detail === 'string'
            ? data.detail
            : 'Unable to analyze this message.',
        )
      }

      setResult(data)
      await loadHistory()
    } catch (err) {
      setError(
        err.message ||
          'Backend connection failed. Check whether the Python server is running.',
      )
    } finally {
      setLoading(false)
    }
  }

  const openHistory = async () => {
    setActivePage('history')
    setSelectedRecord(null)
    await loadHistory()
  }

  const openScanner = () => {
    setActivePage('scanner')
    setSelectedRecord(null)
  }

  const isScam = result?.prediction?.toLowerCase() === 'scam'
  const detectedUrls = result?.urls_found ?? []
  const explanations = result?.explanations ?? []
  const recommendations = result?.safety_recommendations ?? []

  const filteredHistory = history.filter((item) => {
    const prediction = String(item.prediction || '').toLowerCase()

    if (historyFilter === 'scam') {
      return prediction === 'scam'
    }

    if (historyFilter === 'legitimate') {
      return ['legitimate', 'ham', 'safe'].includes(prediction)
    }

    return true
  })

  const formatDate = (value) => {
    if (!value) return 'Date unavailable'

    const date = new Date(
      value.includes('Z') ? value : value.replace(' ', 'T') + 'Z',
    )

    if (Number.isNaN(date.getTime())) {
      return value
    }

    return date.toLocaleString()
  }

  const renderUrlDetails = (urls) => {
    if (!Array.isArray(urls) || urls.length === 0) {
      return <p>No HTTP or HTTPS links were detected.</p>
    }

    return (
      <div className="history-url-list">
        {urls.map((item, index) => (
          <article
            className="url-item"
            key={`${item.url}-${index}`}
          >
            <p className="url-address">
              <strong>Detected URL</strong>
              <br />
              <span>{item.url}</span>
            </p>

            <div className="url-risk-row">
              <strong>Inspection status</strong>
              <span
                className={`url-risk ${
                  item.risk_level === 'High risk' ||
                  item.risk_level === 'Needs review'
                    ? 'url-risk-review'
                    : 'url-risk-clear'
                }`}
              >
                {item.risk_level || 'Unknown'}
              </span>
            </div>

            <div className="url-indicators">
              <strong>Indicators found</strong>

              {item.indicators?.length > 0 ? (
                <ul>
                  {item.indicators.map((indicator, index) => (
                    <li key={`${indicator}-${index}`}>
                      {indicator}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No obvious indicators were found by these checks.</p>
              )}
            </div>
          </article>
        ))}
      </div>
    )
  }

  return (
    <div className="app-container">
      <header className="topbar">
        <a
          className="brand"
          href="#home"
          onClick={openScanner}
        >
          <span className="brand-icon">🛡️</span>
          <span>ScamShield AI</span>
        </a>

        <nav className="navigation" aria-label="Main navigation">
          <button
            type="button"
            className={
              activePage === 'scanner'
                ? 'nav-button active'
                : 'nav-button'
            }
            onClick={openScanner}
          >
            Message Scanner
          </button>

          <button
            type="button"
            className={
              activePage === 'history'
                ? 'nav-button active'
                : 'nav-button'
            }
            onClick={openHistory}
          >
            Analysis History
          </button>
        </nav>
      </header>

      <main id="home" className="main-content">
        <section className="hero-section">
          <p className="eyebrow">
            ● AI-POWERED DIGITAL SAFETY
          </p>

          <h1>
            Stay one step ahead of{' '}
            <span
              className="highlight"
              style={{ marginLeft: '0.25em' }}
            >
              online scams.
            </span>
          </h1>

          <p className="hero-description">
            Analyze suspicious messages and identify potential
            scam indicators before you take action.
          </p>
        </section>

        {activePage === 'scanner' && (
          <>
            <section id="dashboard" className="scanner-card">
              <div className="section-heading">
                <span className="section-icon">🔍</span>

                <div>
                  <h2>Message Scanner</h2>
                  <p>
                    Paste a suspicious SMS, email, or WhatsApp
                    message below.
                  </p>
                </div>
              </div>

              <form onSubmit={analyzeMessage}>
                <label htmlFor="message">
                  Message to analyze
                </label>

                <textarea
                  id="message"
                  value={message}
                  onChange={(event) => {
                    setMessage(event.target.value)
                    setError('')
                  }}
                  placeholder="Paste the message text here."
                  rows={6}
                  maxLength={10000}
                />

                <div className="input-footer">
                  <span>
                    {message.length}/10000 characters
                  </span>

                  <button
                    type="submit"
                    disabled={loading || !message.trim()}
                  >
                    {loading
                      ? 'Analyzing...'
                      : 'Analyze Message →'}
                  </button>
                </div>
              </form>

              {error && (
                <div className="error-message" role="alert">
                  <strong>Analysis failed</strong>
                  <p>{error}</p>
                </div>
              )}

              {result && (
                <div
                  className={`result-card ${
                    isScam
                      ? 'scam-result'
                      : 'legitimate-result'
                  }`}
                  aria-live="polite"
                >
                  <div className="result-heading">
                    <span className="result-icon">
                      {isScam ? '⚠️' : '✅'}
                    </span>

                    <div>
                      <p className="result-label">
                        AI ANALYSIS RESULT
                      </p>

                      <h3>
                        {isScam
                          ? 'Potential Scam Detected'
                          : 'Model Classification Result'}
                      </h3>
                    </div>
                  </div>

                  <div className="result-details">
                    <div className="result-row">
                      <span>Prediction</span>
                      <strong>{result.prediction}</strong>
                    </div>

                    <div className="result-row">
                      <span>Model confidence</span>
                      <strong>
                        {typeof result.confidence === 'number'
                          ? `${(result.confidence * 100).toFixed(2)}%`
                          : 'Not available'}
                      </strong>
                    </div>
                  </div>

                  <div className="warning-box">
                    <strong>
                      {isScam
                        ? '⚠️ Safety warning'
                        : '🛡️ Safety reminder'}
                    </strong>

                    <p>
                      {result.warning ||
                        'Always verify suspicious messages independently.'}
                    </p>
                  </div>

                  <section className="explanation-section">
                    <div className="result-section-heading">
                      <span>🧠</span>

                      <div>
                        <h3>AI Explanations</h3>
                        <p>
                          Indicators identified by the current
                          explanation rules.
                        </p>
                      </div>
                    </div>

                    {explanations.length > 0 ? (
                      <ul className="explanation-list">
                        {explanations.map((item, index) => (
                          <li key={`${item}-${index}`}>
                            <span className="list-icon">⚠️</span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p>No explanation data was returned.</p>
                    )}

                    <p className="section-disclaimer">
                      These explanations come from rule-based text
                      checks. They do not reveal the ML model's
                      internal reasoning and are not proof that a
                      message is fraudulent.
                    </p>
                  </section>

                  <section className="recommendations-section">
                    <div className="result-section-heading">
                      <span>🛡️</span>

                      <div>
                        <h3>Safety Recommendations</h3>
                        <p>
                          Practical steps to help protect yourself.
                        </p>
                      </div>
                    </div>

                    {recommendations.length > 0 ? (
                      <ul className="recommendation-list">
                        {recommendations.map((item, index) => (
                          <li key={`${item}-${index}`}>
                            <span className="list-icon">✓</span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p>No recommendation data was returned.</p>
                    )}
                  </section>

                  <section className="url-analysis">
                    <h3>🔗 URL Inspection</h3>

                    {renderUrlDetails(detectedUrls)}

                    <p className="url-disclaimer">
                      URL inspection uses basic rules. A flagged
                      link is not automatically malicious, and a
                      link without indicators is not guaranteed
                      to be safe.
                    </p>
                  </section>

                  <section className="analyzed-message">
                    <strong>Analyzed message</strong>
                    <p>{result.message}</p>
                  </section>

                  <button
                    type="button"
                    className="secondary-button"
                    onClick={openHistory}
                  >
                    View Saved Analysis History →
                  </button>
                </div>
              )}
            </section>

            <section className="features-section">
              <article className="feature-card">
                <span className="feature-icon">🔍</span>
                <h3>Message Analysis</h3>
                <p>
                  Classify suspicious text using a machine learning
                  model.
                </p>
              </article>

              <article className="feature-card">
                <span className="feature-icon">🔗</span>
                <h3>URL Inspection</h3>
                <p>
                  Extract website links and review potential
                  warning indicators.
                </p>
              </article>

              <article className="feature-card">
                <span className="feature-icon">🧠</span>
                <h3>AI Explanations</h3>
                <p>
                  Understand potential warning signs and learn
                  practical online safety steps.
                </p>
              </article>
            </section>
          </>
        )}

        {activePage === 'history' && (
          <section className="scanner-card history-page">
            <div className="section-heading">
              <span className="section-icon">🕘</span>

              <div>
                <h2>Analysis History</h2>
                <p>
                  View messages previously analyzed and saved in
                  your local database.
                </p>
              </div>
            </div>

            <div className="history-toolbar">
              <label htmlFor="history-filter">
                Filter results
              </label>

              <select
                id="history-filter"
                value={historyFilter}
                onChange={(event) =>
                  setHistoryFilter(event.target.value)
                }
              >
                <option value="all">All results</option>
                <option value="scam">Scam only</option>
                <option value="legitimate">
                  Legitimate / safe labels
                </option>
              </select>

              <button
                type="button"
                onClick={loadHistory}
                disabled={historyLoading}
              >
                {historyLoading
                  ? 'Refreshing...'
                  : '↻ Refresh History'}
              </button>
            </div>

            {historyError && (
              <div className="error-message" role="alert">
                <strong>Could not load history</strong>
                <p>{historyError}</p>
              </div>
            )}

            {historyLoading && history.length === 0 && (
              <p>Loading saved analyses...</p>
            )}

            {!historyLoading &&
              !historyError &&
              history.length === 0 && (
                <div className="history-empty">
                  <span>📭</span>
                  <h3>No saved analyses yet</h3>
                  <p>
                    Analyze a message first. Successful results
                    will appear here.
                  </p>

                  <button
                    type="button"
                    onClick={openScanner}
                  >
                    Go to Message Scanner
                  </button>
                </div>
              )}

            {history.length > 0 && (
              <>
                <div
                  className="history-summary"
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    alignItems: 'center',
                    columnGap: '8px',
                    rowGap: '4px',
                  }}
                >
                  <strong>{filteredHistory.length}</strong>

                  <span>
                    {filteredHistory.length === 1
                      ? 'record shown'
                      : 'records shown'}
                  </span>

                  <span>·</span>

                  <span>
                    {history.length} loaded from the latest
                    50 records
                  </span>
                </div>

                {filteredHistory.length === 0 ? (
                  <p>No records match this filter.</p>
                ) : (
                  <div className="history-list">
                    {filteredHistory.map((item) => {
                      const recordIsScam =
                        String(item.prediction).toLowerCase() ===
                        'scam'

                      const isSelected =
                        selectedRecord?.id === item.id

                      return (
                        <article
                          className="history-record"
                          key={item.id}
                        >
                          <div className="history-record-top">
                            <span
                              className={`history-badge ${
                                recordIsScam
                                  ? 'history-badge-scam'
                                  : 'history-badge-other'
                              }`}
                            >
                              {item.prediction || 'Unknown'}
                            </span>

                            <span className="history-date">
                              {formatDate(item.created_at)}
                            </span>
                          </div>

                          <p className="history-message">
                            {item.message}
                          </p>

                          <div
                            className="history-record-meta"
                            style={{
                              display: 'flex',
                              flexWrap: 'wrap',
                              alignItems: 'center',
                              columnGap: '18px',
                              rowGap: '8px',
                            }}
                          >
                            <span>
                              Confidence:{' '}
                              <strong>
                                {typeof item.confidence === 'number'
                                  ? `${(item.confidence * 100).toFixed(2)}%`
                                  : 'N/A'}
                              </strong>
                            </span>

                            <span>
                              URLs:{' '}
                              <strong>
                                {item.urls_found?.length ?? 0}
                              </strong>
                            </span>
                          </div>

                          <button
                            type="button"
                            className="secondary-button"
                            onClick={() =>
                              setSelectedRecord(
                                isSelected ? null : item,
                              )
                            }
                          >
                            {isSelected
                              ? 'Hide Details ↑'
                              : 'View Details →'}
                          </button>

                          {isSelected && (
                            <div className="history-details">
                              <h3>Saved Analysis Details</h3>

                              <div className="result-row">
                                <span>Record ID</span>
                                <strong>{item.id}</strong>
                              </div>

                              <div className="result-row">
                                <span>Prediction</span>
                                <strong>{item.prediction}</strong>
                              </div>

                              <h4>URL Inspection</h4>
                              {renderUrlDetails(item.urls_found)}

                              <h4>Explanations</h4>

                              {item.explanations?.length > 0 ? (
                                <ul className="explanation-list">
                                  {item.explanations.map(
                                    (entry, index) => (
                                      <li key={`${entry}-${index}`}>
                                        <span className="list-icon">
                                          •
                                        </span>
                                        <span>{entry}</span>
                                      </li>
                                    ),
                                  )}
                                </ul>
                              ) : (
                                <p>No saved explanations.</p>
                              )}

                              <h4>Safety Recommendations</h4>

                              {item.safety_recommendations?.length >
                              0 ? (
                                <ul className="recommendation-list">
                                  {item.safety_recommendations.map(
                                    (entry, index) => (
                                      <li key={`${entry}-${index}`}>
                                        <span className="list-icon">
                                          ✓
                                        </span>
                                        <span>{entry}</span>
                                      </li>
                                    ),
                                  )}
                                </ul>
                              ) : (
                                <p>No saved recommendations.</p>
                              )}
                            </div>
                          )}
                        </article>
                      )
                    })}
                  </div>
                )}
              </>
            )}

            <p className="section-disclaimer">
              History is retrieved from your local SQLite database.
              Avoid saving real passwords, OTPs, or other sensitive
              personal data.
            </p>

            <button
              type="button"
              className="secondary-button"
              onClick={openScanner}
            >
              ← Back to Message Scanner
            </button>
          </section>
        )}

        <footer className="footer">
          <p>
            ScamShield AI · AI predictions are not a guarantee of safety.
          </p>
        </footer>
      </main>
    </div>
  )
}

export default App
