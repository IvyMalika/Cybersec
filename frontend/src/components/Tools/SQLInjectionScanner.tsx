import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
  CircularProgress,
  Divider,
  Fade,
  InputAdornment,
  IconButton,
  Chip
} from '@mui/material';
import { ExpandMore as ExpandMoreIcon, Search as SearchIcon, Info as InfoIcon, Storage as StorageIcon, Assignment as AssignmentIcon } from '@mui/icons-material';
import axios from 'axios';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import HourglassEmptyIcon from '@mui/icons-material/HourglassEmpty';
import Timeline from '@mui/lab/Timeline';
import TimelineItem from '@mui/lab/TimelineItem';
import TimelineSeparator from '@mui/lab/TimelineSeparator';
import TimelineConnector from '@mui/lab/TimelineConnector';
import TimelineContent from '@mui/lab/TimelineContent';
import TimelineDot from '@mui/lab/TimelineDot';
import TableChartIcon from '@mui/icons-material/TableChart';

const defaultOptions = {
  risk: 2,
  level: 2,
};

const scanSteps = [
  { key: 'scan', label: 'Initial Scan', icon: <SearchIcon /> },
  { key: 'dbs', label: 'List Databases', icon: <StorageIcon /> },
  { key: 'tables', label: 'List Tables', icon: <TableChartIcon /> },
  { key: 'dump', label: 'Dump Table', icon: <AssignmentIcon /> },
];

const getStepStatus = (step: string, state: any) => {
  if (state.loading === step) return 'running';
  if (state.completed.includes(step)) return 'done';
  if (state.errorStep === step) return 'error';
  return 'idle';
};

const stepDetails: Record<string, { desc: string; command: (url: string, opts: any, db?: string, table?: string) => string; outcome: string }> = {
  scan: {
    desc: 'Testing the provided URL for SQL injection vulnerabilities using various techniques.',
    command: (url, opts) => `sqlmap -u "${url}" --batch${opts.risk ? ` --risk ${opts.risk}` : ''}${opts.level ? ` --level ${opts.level}` : ''}`,
    outcome: 'If vulnerable, you’ll see details about the injection point and type.'
  },
  dbs: {
    desc: 'Enumerating all databases available on the target system.',
    command: (url, opts) => `sqlmap -u "${url}" --dbs --batch${opts.risk ? ` --risk ${opts.risk}` : ''}${opts.level ? ` --level ${opts.level}` : ''}`,
    outcome: 'A list of database names will be displayed.'
  },
  tables: {
    desc: 'Listing all tables in the selected database.',
    command: (url, opts, db) => `sqlmap -u "${url}" -D ${db} --tables --batch${opts.risk ? ` --risk ${opts.risk}` : ''}${opts.level ? ` --level ${opts.level}` : ''}`,
    outcome: 'A list of table names in the selected database will be displayed.'
  },
  dump: {
    desc: 'Dumping all data from the selected table in the selected database.',
    command: (url, opts, db, table) => `sqlmap -u "${url}" -D ${db} -T ${table} --dump --batch${opts.risk ? ` --risk ${opts.risk}` : ''}${opts.level ? ` --level ${opts.level}` : ''}`,
    outcome: 'The contents of the selected table will be displayed.'
  }
};

const SQLInjectionScanner: React.FC = () => {
  const [url, setUrl] = useState('');
  const [options, setOptions] = useState(defaultOptions);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showOptions, setShowOptions] = useState(false);
  // Advanced exploitation state
  const [dbs, setDbs] = useState<string | null>(null);
  const [tables, setTables] = useState<string | null>(null);
  const [dump, setDump] = useState<string | null>(null);
  const [exploitLoading, setExploitLoading] = useState<string | null>(null);
  const [selectedDb, setSelectedDb] = useState('');
  const [selectedTable, setSelectedTable] = useState('');
  const [completedSteps, setCompletedSteps] = useState<string[]>([]);
  const [errorStep, setErrorStep] = useState<string | null>(null);
  // Add a status log state
  const [statusLog, setStatusLog] = useState<string[]>([]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    setError(null);
    setDbs(null);
    setTables(null);
    setDump(null);
    setSelectedDb('');
    setSelectedTable('');
    setCompletedSteps([]);
    setErrorStep(null);
    setStatusLog([]);
    try {
      setStatusLog(log => [...log, 'Starting initial scan...']);
      const res = await axios.post('/api/tools/osint/sqlmap', {
        url,
        risk: options.risk,
        level: options.level,
      });
      setResult(res.data.output || '');
      setCompletedSteps(prev => [...new Set([...prev, 'scan'])]);
      setStatusLog(log => [...log, 'Initial scan completed.']);
    } catch (err: any) {
      setError(err.response?.data?.error || 'SQLmap scan failed or is not available.');
      setErrorStep('scan');
      setStatusLog(log => [...log, 'Initial scan failed.']);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  // Helper to call advanced sqlmap options
  const runSqlmapOption = async (extra: any, setOutput: (s: string) => void, stepKey: string) => {
    setExploitLoading(stepKey);
    setError(null);
    setErrorStep(null);
    setStatusLog(log => [...log, `Starting ${scanSteps.find(s => s.key === stepKey)?.label || stepKey}...`]);
    try {
      const res = await axios.post('/api/tools/osint/sqlmap', {
        url,
        risk: options.risk,
        level: options.level,
        ...extra,
      });
      setOutput(res.data.output || '');
      setCompletedSteps(prev => [...new Set([...prev, stepKey])]);
      setStatusLog(log => [...log, `${scanSteps.find(s => s.key === stepKey)?.label || stepKey} completed.`]);
    } catch (err: any) {
      setError(err.response?.data?.error || 'SQLmap advanced option failed.');
      setErrorStep(stepKey);
      setStatusLog(log => [...log, `${scanSteps.find(s => s.key === stepKey)?.label || stepKey} failed.`]);
    } finally {
      setExploitLoading(null);
    }
  };

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto', display: 'flex', gap: 4 }}>
      {/* Main content */}
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography variant="h4" sx={{ mb: 3, fontWeight: 700 }}>
          SQL Injection Scanner
        </Typography>
        <Alert severity="info" sx={{ mb: 2 }}>
          Enter a test URL (with a query parameter) to scan for SQL injection vulnerabilities using <b>sqlmap</b>.<br />
          <b>Example:</b> <code>http://example.com/page?id=1</code>
        </Alert>
        <form onSubmit={handleSubmit}>
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <TextField
                label="Test URL (e.g. http://example.com/page?id=1)"
                value={url}
                onChange={e => setUrl(e.target.value)}
                fullWidth
                required
                sx={{ mb: 2 }}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <Tooltip title="URL to test for SQL injection" arrow>
                        <SearchIcon />
                      </Tooltip>
                    </InputAdornment>
                  ),
                }}
              />
              <Button
                type="button"
                variant="text"
                onClick={() => setShowOptions(v => !v)}
                sx={{ mb: 2 }}
                startIcon={<InfoIcon />}
              >
                {showOptions ? 'Hide Advanced Options' : 'Show Advanced Options'}
              </Button>
              <Fade in={showOptions}>
                <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                  <Tooltip title="Risk: 0 (default), 1 (medium), 2 (aggressive)" arrow>
                    <TextField
                      label="Risk"
                      type="number"
                      value={options.risk}
                      onChange={e => setOptions(o => ({ ...o, risk: Number(e.target.value) }))}
                      inputProps={{ min: 0, max: 3 }}
                      sx={{ width: 120 }}
                    />
                  </Tooltip>
                  <Tooltip title="Level: 1 (default) to 5 (most tests)" arrow>
                    <TextField
                      label="Level"
                      type="number"
                      value={options.level}
                      onChange={e => setOptions(o => ({ ...o, level: Number(e.target.value) }))}
                      inputProps={{ min: 1, max: 5 }}
                      sx={{ width: 120 }}
                    />
                  </Tooltip>
                </Box>
              </Fade>
              <Divider sx={{ my: 2 }} />
              <Button
                type="submit"
                variant="contained"
                color="primary"
                fullWidth
                disabled={loading || !url}
                startIcon={loading ? <CircularProgress size={20} /> : <SearchIcon />}
                aria-label="Start SQL injection scan"
              >
                {loading ? 'Scanning...' : 'Scan for SQL Injection'}
              </Button>
            </CardContent>
          </Card>
        </form>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>
        )}
        {/* Results as expandable cards */}
        {loading || exploitLoading ? (
          <Card sx={{ mb: 3, background: '#f8fafc', border: '1px solid #eee', borderRadius: 2 }}>
            <CardContent sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 180 }}>
              <CircularProgress size={48} sx={{ mb: 2 }} />
              <Typography variant="h6" sx={{ mb: 1 }}>
                Processing {exploitLoading ? scanSteps.find(s => s.key === exploitLoading)?.label : 'Scan'}...
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Please wait while the scan is running. This may take a few moments.
              </Typography>
            </CardContent>
          </Card>
        ) : result && (
          <Accordion defaultExpanded aria-label="sqlmap results">
            <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="sqlmap-content" id="sqlmap-header">
              <Tooltip title="sqlmap SQL injection scan" arrow>
                <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>sqlmap Results</Typography>
              </Tooltip>
              <Chip
                label={exploitLoading === 'scan' ? 'Running' : completedSteps.includes('scan') ? 'Done' : errorStep === 'scan' ? 'Error' : 'Idle'}
                color={exploitLoading === 'scan' ? 'info' : completedSteps.includes('scan') ? 'success' : errorStep === 'scan' ? 'error' : 'default'}
                size="small"
                sx={{ ml: 2 }}
              />
            </AccordionSummary>
            <AccordionDetails>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Button size="small" startIcon={<ContentCopyIcon />} onClick={() => handleCopy(result)} sx={{ mr: 2 }}>
                  Copy Output
                </Button>
                {exploitLoading === 'scan' && <CircularProgress size={18} sx={{ ml: 1 }} />}
                {completedSteps.includes('scan') && <CheckCircleIcon color="success" sx={{ ml: 1 }} />}
                {errorStep === 'scan' && <ErrorIcon color="error" sx={{ ml: 1 }} />}
              </Box>
              <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 13, background: '#f8fafc', padding: 12, borderRadius: 4, border: '1px solid #eee' }}>{result}</pre>
              {/* Advanced exploitation options and results as before, but update runSqlmapOption calls to pass stepKey... */}
              <Alert severity="warning" sx={{ mt: 2, mb: 2 }}>
                <b>Warning:</b> The following actions are for <b>authorized penetration testing and research only</b>.<br />
                Unauthorized exploitation is illegal and unethical.
              </Alert>
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 2 }}>
                <Button
                  variant="outlined"
                  color="primary"
                  disabled={exploitLoading === 'dbs' || !url}
                  onClick={() => runSqlmapOption({ type: 'dbs', dbs: true }, setDbs, 'dbs')}
                  startIcon={exploitLoading === 'dbs' ? <CircularProgress size={18} /> : <SearchIcon />}
                >
                  List Databases
                </Button>
                <TextField
                  label="Database Name"
                  value={selectedDb}
                  onChange={e => setSelectedDb(e.target.value)}
                  sx={{ width: 180 }}
                  size="small"
                  placeholder="targetdb"
                />
                <Button
                  variant="outlined"
                  color="primary"
                  disabled={exploitLoading === 'tables' || !url || !selectedDb}
                  onClick={() => runSqlmapOption({ type: 'tables', tables: true, db: selectedDb }, setTables, 'tables')}
                  startIcon={exploitLoading === 'tables' ? <CircularProgress size={18} /> : <SearchIcon />}
                >
                  List Tables
                </Button>
                <TextField
                  label="Table Name"
                  value={selectedTable}
                  onChange={e => setSelectedTable(e.target.value)}
                  sx={{ width: 180 }}
                  size="small"
                  placeholder="users"
                />
                <Button
                  variant="outlined"
                  color="primary"
                  disabled={exploitLoading === 'dump' || !url || !selectedDb || !selectedTable}
                  onClick={() => runSqlmapOption({ type: 'dump', dump: true, db: selectedDb, table: selectedTable }, setDump, 'dump')}
                  startIcon={exploitLoading === 'dump' ? <CircularProgress size={18} /> : <SearchIcon />}
                >
                  Dump Table
                </Button>
              </Box>
              {dbs && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>Databases</Typography>
                  <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 13, background: '#f8fafc', padding: 8, borderRadius: 4, border: '1px solid #eee' }}>{dbs}</pre>
                </Box>
              )}
              {tables && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>Tables in {selectedDb}</Typography>
                  <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 13, background: '#f8fafc', padding: 8, borderRadius: 4, border: '1px solid #eee' }}>{tables}</pre>
                </Box>
              )}
              {dump && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>Dump of {selectedTable} in {selectedDb}</Typography>
                  <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 13, background: '#f8fafc', padding: 8, borderRadius: 4, border: '1px solid #eee' }}>{dump}</pre>
                </Box>
              )}
            </AccordionDetails>
          </Accordion>
        )}
        {/* Repeat for dbs, tables, dump with similar cards/expanders, chips, copy buttons, etc. */}
        {dbs && (
          <Accordion defaultExpanded aria-label="dbs results">
            <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="dbs-content" id="dbs-header">
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Databases</Typography>
              <Chip
                label={exploitLoading === 'dbs' ? 'Running' : completedSteps.includes('dbs') ? 'Done' : errorStep === 'dbs' ? 'Error' : 'Idle'}
                color={exploitLoading === 'dbs' ? 'info' : completedSteps.includes('dbs') ? 'success' : errorStep === 'dbs' ? 'error' : 'default'}
                size="small"
                sx={{ ml: 2 }}
              />
            </AccordionSummary>
            <AccordionDetails>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Button size="small" startIcon={<ContentCopyIcon />} onClick={() => handleCopy(dbs)} sx={{ mr: 2 }}>
                  Copy Output
                </Button>
                {exploitLoading === 'dbs' && <CircularProgress size={18} sx={{ ml: 1 }} />}
                {completedSteps.includes('dbs') && <CheckCircleIcon color="success" sx={{ ml: 1 }} />}
                {errorStep === 'dbs' && <ErrorIcon color="error" sx={{ ml: 1 }} />}
              </Box>
              <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 13, background: '#f8fafc', padding: 8, borderRadius: 4, border: '1px solid #eee' }}>{dbs}</pre>
            </AccordionDetails>
          </Accordion>
        )}
        {tables && (
          <Accordion defaultExpanded aria-label="tables results">
            <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="tables-content" id="tables-header">
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Tables in {selectedDb}</Typography>
              <Chip
                label={exploitLoading === 'tables' ? 'Running' : completedSteps.includes('tables') ? 'Done' : errorStep === 'tables' ? 'Error' : 'Idle'}
                color={exploitLoading === 'tables' ? 'info' : completedSteps.includes('tables') ? 'success' : errorStep === 'tables' ? 'error' : 'default'}
                size="small"
                sx={{ ml: 2 }}
              />
            </AccordionSummary>
            <AccordionDetails>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Button size="small" startIcon={<ContentCopyIcon />} onClick={() => handleCopy(tables)} sx={{ mr: 2 }}>
                  Copy Output
                </Button>
                {exploitLoading === 'tables' && <CircularProgress size={18} sx={{ ml: 1 }} />}
                {completedSteps.includes('tables') && <CheckCircleIcon color="success" sx={{ ml: 1 }} />}
                {errorStep === 'tables' && <ErrorIcon color="error" sx={{ ml: 1 }} />}
              </Box>
              <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 13, background: '#f8fafc', padding: 8, borderRadius: 4, border: '1px solid #eee' }}>{tables}</pre>
            </AccordionDetails>
          </Accordion>
        )}
        {dump && (
          <Accordion defaultExpanded aria-label="dump results">
            <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="dump-content" id="dump-header">
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Dump of {selectedTable} in {selectedDb}</Typography>
              <Chip
                label={exploitLoading === 'dump' ? 'Running' : completedSteps.includes('dump') ? 'Done' : errorStep === 'dump' ? 'Error' : 'Idle'}
                color={exploitLoading === 'dump' ? 'info' : completedSteps.includes('dump') ? 'success' : errorStep === 'dump' ? 'error' : 'default'}
                size="small"
                sx={{ ml: 2 }}
              />
            </AccordionSummary>
            <AccordionDetails>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Button size="small" startIcon={<ContentCopyIcon />} onClick={() => handleCopy(dump)} sx={{ mr: 2 }}>
                  Copy Output
                </Button>
                {exploitLoading === 'dump' && <CircularProgress size={18} sx={{ ml: 1 }} />}
                {completedSteps.includes('dump') && <CheckCircleIcon color="success" sx={{ ml: 1 }} />}
                {errorStep === 'dump' && <ErrorIcon color="error" sx={{ ml: 1 }} />}
              </Box>
              <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 13, background: '#f8fafc', padding: 8, borderRadius: 4, border: '1px solid #eee' }}>{dump}</pre>
            </AccordionDetails>
          </Accordion>
        )}
        {/* At the bottom of the main result area, show the status log */}
        {statusLog.length > 0 && (
          <Card sx={{ mt: 3, background: '#f8fafc', border: '1px solid #eee', borderRadius: 2 }}>
            <CardContent>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Scan Status Log</Typography>
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13 }}>
                {statusLog.map((msg, idx) => (
                  <li key={idx}>{msg}</li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}
      </Box>
      {/* Sidebar: scan process timeline and process details */}
      {(loading || result || dbs || tables || dump) && (
        <Box sx={{ width: 320, minWidth: 220, ml: 2, background: '#181c24', borderRadius: 2, p: 2, boxShadow: 2, height: 'fit-content', position: 'sticky', top: 32 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2, color: '#fff' }}>
            Scan Process
          </Typography>
          <Timeline position="right" sx={{ p: 0, m: 0 }}>
            {scanSteps.map(step => {
              const status = getStepStatus(step.key, { loading: exploitLoading, completed: completedSteps, errorStep });
              return (
                <TimelineItem key={step.key}>
                  <TimelineSeparator>
                    <TimelineDot color={
                      status === 'done' ? 'success' :
                      status === 'running' ? 'info' :
                      status === 'error' ? 'error' : 'grey'
                    }>
                      {step.icon}
                    </TimelineDot>
                    <TimelineConnector />
                  </TimelineSeparator>
                  <TimelineContent>
                    <Typography sx={{ color: '#fff', fontWeight: 500 }}>{step.label}</Typography>
                    {status === 'running' && <CircularProgress size={14} sx={{ ml: 1, color: '#fff' }} />}
                    {status === 'done' && <CheckCircleIcon color="success" sx={{ ml: 1 }} />}
                    {status === 'error' && <ErrorIcon color="error" sx={{ ml: 1 }} />}
                  </TimelineContent>
                </TimelineItem>
              );
            })}
          </Timeline>
          {/* Process Details Panel */}
          <Box sx={{ mt: 3, background: '#222', borderRadius: 2, p: 2, color: '#fff' }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Process Details</Typography>
            {scanSteps.map(step => {
              const isCurrent = (exploitLoading === step.key) || (!exploitLoading && completedSteps.includes(step.key));
              let db = selectedDb;
              let table = selectedTable;
              if (step.key === 'scan') db = table = undefined;
              if (step.key === 'dbs') table = undefined;
              return (
                <Box key={step.key} sx={{ mb: 2, opacity: isCurrent ? 1 : 0.6 }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>{step.label}</Typography>
                  <Typography variant="caption" sx={{ display: 'block', mb: 0.5 }}>{stepDetails[step.key].desc}</Typography>
                  <Typography variant="caption" sx={{ display: 'block', color: '#90caf9', mb: 0.5 }}>
                    <b>Command:</b> <code>{stepDetails[step.key].command(url, options, db, table)}</code>
                  </Typography>
                  <Typography variant="caption" sx={{ display: 'block', color: '#a5d6a7' }}>{stepDetails[step.key].outcome}</Typography>
                </Box>
              );
            })}
          </Box>
        </Box>
      )}
    </Box>
  );
};

export default SQLInjectionScanner; 