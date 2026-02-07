import { useState, useRef, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import { Input } from '@stevederico/skateboard-ui/shadcn/ui/input';
import { Spinner } from '@stevederico/skateboard-ui/shadcn/ui/spinner';
import { Kbd } from '@stevederico/skateboard-ui/shadcn/ui/kbd';

const TLDS = ['com', 'net', 'org', 'io', 'dev', 'app', 'co', 'xyz', 'ai', 'shop', 'site', 'tech'];

/**
 * Determine backend URL based on environment
 * @returns {string} Base API URL
 */
function getApiBase() {
  if (typeof window !== 'undefined' && window.location.port === '5173') {
    return 'http://localhost:8000/api';
  }
  return '/api';
}

/**
 * Domain availability checker view
 *
 * Renders a search input with debounced RDAP+DNS lookups across 12 TLDs.
 * Results display as a compact two-column list with green/red dot indicators.
 * Available domains copy to clipboard on click (no external registrar links).
 *
 * @component
 * @returns {JSX.Element} Domain checker view
 */
export default function HomeView() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);
  const inputRef = useRef(null);
  const debounceRef = useRef(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const checkDomain = useCallback(async (name) => {
    if (!name || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(name)) {
      setResults([]);
      setHasSearched(false);
      return;
    }

    setIsLoading(true);
    setHasSearched(true);
    setResults(TLDS.map((tld) => ({
      tld,
      domain: `${name}.${tld}`,
      available: null,
      status: 'loading'
    })));

    try {
      const apiBase = getApiBase();
      const res = await fetch(`${apiBase}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: name }),
        cache: 'no-store'
      });
      const data = await res.json();
      setResults(data);
    } catch (err) {
      console.error('Domain check failed');
      setResults(TLDS.map((tld) => ({
        tld,
        domain: `${name}.${tld}`,
        available: null,
        status: 'error'
      })));
    } finally {
      setIsLoading(false);
    }
  }, []);

  const handleInputChange = useCallback((e) => {
    const raw = e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '');
    setQuery(raw);

    if (debounceRef.current) clearTimeout(debounceRef.current);

    if (!raw) {
      setResults([]);
      setHasSearched(false);
      return;
    }

    debounceRef.current = setTimeout(() => {
      checkDomain(raw);
    }, 300);
  }, [checkDomain]);

  const availableCount = results.filter((r) => r.available === true).length;
  const takenCount = results.filter((r) => r.available === false).length;

  return (
    <>
      <div className="flex flex-1 flex-col items-center">
        <div className="w-full max-w-2xl px-4 py-8 md:py-12">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold tracking-tight mb-2">Find your domain</h1>
            <p className="text-muted-foreground text-sm">
              Direct WHOIS lookup — your queries are never stored or shared
            </p>
          </div>

          <div className="relative mb-8">
            <Input
              ref={inputRef}
              type="text"
              placeholder="Enter a domain name..."
              value={query}
              onChange={handleInputChange}
              className="h-14 text-lg px-5 pr-24 rounded-full"
              autoComplete="off"
              autoFocus
              spellCheck={false}
            />
            <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1.5 text-muted-foreground">
              {isLoading ? (
                <Spinner className="h-4 w-4" />
              ) : (
                <span className="text-xs hidden sm:inline">
                  <Kbd>auto</Kbd>
                </span>
              )}
            </div>
          </div>

          {hasSearched && !isLoading && results.length > 0 && (
            <div className="flex items-center gap-3 mb-4 text-sm text-muted-foreground">
              {availableCount > 0 && (
                <span className="text-emerald-500 font-medium">
                  {availableCount} available
                </span>
              )}
              {takenCount > 0 && (
                <span className="text-red-500 font-medium">
                  {takenCount} taken
                </span>
              )}
            </div>
          )}

          {hasSearched && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-0">
              {results.map((result) => (
                <DomainRow key={result.tld} result={result} />
              ))}
            </div>
          )}

          {!hasSearched && (
            <div className="text-center text-muted-foreground text-sm mt-12">
              <p>Type a name to check availability across 12 TLDs</p>
              <p className="mt-1 text-xs opacity-60">
                .com .net .org .io .dev .app .co .xyz .ai .shop .site .tech
              </p>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

/**
 * Copy domain name to clipboard and show toast notification
 *
 * @param {string} domain - Domain name to copy
 */
function copyDomain(domain) {
  navigator.clipboard.writeText(domain).then(() => {
    toast.success(`Copied ${domain}`);
  }).catch(() => {
    toast.error('Failed to copy');
  });
}

/**
 * Single domain result row with colored dot indicator
 *
 * Green dot = WHOIS/RDAP-confirmed available (click to copy).
 * Yellow dot = DNS-inferred likely available (click to copy, less certain).
 * Red dot = taken (muted text). Gray dot = unknown/loading.
 *
 * @component
 * @param {Object} props
 * @param {Object} props.result - Domain check result
 * @param {string} props.result.tld - Top-level domain
 * @param {string} props.result.domain - Full domain name
 * @param {boolean|null} props.result.available - Availability (null = unknown)
 * @param {string} props.result.status - Status string
 * @param {string} [props.result.method] - Check method ("whois", "rdap", or "dns")
 * @returns {JSX.Element} Domain result row
 */
function DomainRow({ result }) {
  const { domain, available, status, method } = result;
  const isLoading = status === 'loading';
  const isDNS = method === 'dns';

  if (isLoading) {
    return (
      <div className="flex items-center gap-3 py-2.5 px-1 border-b border-border/40">
        <span className="h-2.5 w-2.5 rounded-full bg-muted-foreground/30 animate-pulse shrink-0" />
        <span className="text-sm text-muted-foreground/50">{domain}</span>
      </div>
    );
  }

  if (available === true) {
    return (
      <button
        onClick={() => copyDomain(domain)}
        className="flex items-center gap-3 py-2.5 px-1 border-b border-border/40 hover:bg-accent/50 transition-colors cursor-pointer group w-full text-left"
      >
        <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${isDNS ? 'bg-yellow-500' : 'bg-emerald-500'}`} />
        <span className="text-sm font-medium group-hover:underline">{domain}</span>
        {isDNS && <span className="text-xs text-muted-foreground/50 ml-auto">likely</span>}
      </button>
    );
  }

  if (available === false) {
    return (
      <div className="flex items-center gap-3 py-2.5 px-1 border-b border-border/40">
        <span className="h-2.5 w-2.5 rounded-full bg-red-500 shrink-0" />
        <span className="text-sm text-muted-foreground">{domain}</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-3 py-2.5 px-1 border-b border-border/40">
      <span className="h-2.5 w-2.5 rounded-full bg-muted-foreground/40 shrink-0" />
      <span className="text-sm text-muted-foreground/60">{domain}</span>
    </div>
  );
}
