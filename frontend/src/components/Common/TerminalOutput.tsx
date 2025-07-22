import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Typography,
  Paper,
  IconButton,
  Tooltip,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  Button,
} from '@mui/material';
import {
  ContentCopy as CopyIcon,
  Fullscreen as FullscreenIcon,
  Download as DownloadIcon,
  Clear as ClearIcon,
  FilterList as FilterIcon,
} from '@mui/icons-material';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { FixedSizeList as List } from 'react-window';
import { colors } from '../../theme/theme';
import { JobResult } from '../../types/api';

interface TerminalOutputProps {
  jobId: number | null;
  results: JobResult[];
  title?: string;
  maxHeight?: number;
}

const TerminalOutput: React.FC<TerminalOutputProps> = ({
  jobId,
  results = [], // Default to empty array
  title = 'Output',
  maxHeight = 400,
}) => {
  const [filter, setFilter] = useState<string>('all');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const outputRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<List>(null);

  const filteredResults = results.filter(result => {
    if (filter === 'all') return true;
    return result.severity === filter;
  });

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return colors.severity.critical;
      case 'high':
        return colors.severity.high;
      case 'medium':
        return colors.severity.medium;
      case 'low':
        return colors.severity.low;
      default:
        return colors.severity.info;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const handleCopy = () => {
    const content = filteredResults.map(result => 
      `[${formatTimestamp(result.created_at)}] ${result.content}`
    ).join('\n');
    
    navigator.clipboard.writeText(content);
  };

  const handleDownload = () => {
    const content = filteredResults.map(result => 
      `[${formatTimestamp(result.created_at)}] ${result.content}`
    ).join('\n');
    
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `output_${jobId}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleClear = () => {
    // This would typically clear the output or refresh the data
    console.log('Clear output');
  };

  useEffect(() => {
    if (autoScroll && listRef.current) {
      listRef.current.scrollToItem(filteredResults.length - 1);
    }
  }, [filteredResults.length, autoScroll]);

  const ResultItem = ({ index, style }: { index: number; style: React.CSSProperties }) => {
    const result = filteredResults[index];
    
    return (
      <div style={style}>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: 1,
            p: 1,
            borderBottom: `1px solid ${colors.border.primary}`,
            fontFamily: 'monospace',
            fontSize: '0.875rem',
          }}
        >
          <Typography
            variant="caption"
            sx={{
              color: colors.text.secondary,
              minWidth: 80,
              fontFamily: 'monospace',
            }}
          >
            {formatTimestamp(result.created_at)}
          </Typography>
          
          <Chip
            label={result.severity}
            size="small"
            sx={{
              backgroundColor: getSeverityColor(result.severity) + '30',
              color: getSeverityColor(result.severity),
              fontSize: '0.75rem',
              height: 20,
              minWidth: 60,
            }}
          />
          
          <Box sx={{ flex: 1 }}>
            <SyntaxHighlighter
              language="bash"
              style={vscDarkPlus}
              customStyle={{
                margin: 0,
                padding: 0,
                background: 'transparent',
                fontSize: '0.875rem',
                fontFamily: 'monospace',
              }}
              wrapLines
              wrapLongLines
            >
              {result.content}
            </SyntaxHighlighter>
          </Box>
        </Box>
      </div>
    );
  };

  return (
    <Paper
      ref={outputRef}
      sx={{
        backgroundColor: colors.terminal.background,
        border: `1px solid ${colors.border.primary}`,
        borderRadius: 1,
        overflow: 'hidden',
        height: isFullscreen ? '100vh' : 'auto',
        maxHeight: isFullscreen ? 'none' : maxHeight,
        position: isFullscreen ? 'fixed' : 'relative',
        top: isFullscreen ? 0 : 'auto',
        left: isFullscreen ? 0 : 'auto',
        right: isFullscreen ? 0 : 'auto',
        bottom: isFullscreen ? 0 : 'auto',
        zIndex: isFullscreen ? 9999 : 'auto',
      }}
    >
      {/* Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          p: 2,
          borderBottom: `1px solid ${colors.border.primary}`,
          backgroundColor: colors.background.paper,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 600 }}>
            {title}
          </Typography>
          <Chip
            label={`${filteredResults.length} lines`}
            size="small"
            sx={{
              backgroundColor: colors.primary.main + '30',
              color: colors.primary.main,
            }}
          />
        </Box>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Filter</InputLabel>
            <Select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              label="Filter"
            >
              <MenuItem value="all">All</MenuItem>
              <MenuItem value="critical">Critical</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="info">Info</MenuItem>
            </Select>
          </FormControl>

          <Button
            size="small"
            variant={autoScroll ? 'contained' : 'outlined'}
            onClick={() => setAutoScroll(!autoScroll)}
            sx={{
              backgroundColor: autoScroll ? colors.primary.main : 'transparent',
              borderColor: colors.primary.main,
              color: autoScroll ? colors.background.default : colors.primary.main,
            }}
          >
            Auto-scroll
          </Button>

          <Tooltip title="Copy Output">
            <IconButton size="small" onClick={handleCopy}>
              <CopyIcon fontSize="small" />
            </IconButton>
          </Tooltip>

          <Tooltip title="Download Output">
            <IconButton size="small" onClick={handleDownload}>
              <DownloadIcon fontSize="small" />
            </IconButton>
          </Tooltip>

          <Tooltip title="Clear Output">
            <IconButton size="small" onClick={handleClear}>
              <ClearIcon fontSize="small" />
            </IconButton>
          </Tooltip>

          <Tooltip title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}>
            <IconButton
              size="small"
              onClick={() => setIsFullscreen(!isFullscreen)}
            >
              <FullscreenIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Output Content */}
      <Box sx={{ height: `calc(100% - 64px)` }}>
        {filteredResults.length > 0 ? (
          <List
            ref={listRef}
            height={isFullscreen ? window.innerHeight - 64 : maxHeight - 64}
            itemCount={filteredResults.length}
            itemSize={50}
            style={{
              backgroundColor: colors.terminal.background,
            }}
          >
            {ResultItem}
          </List>
        ) : (
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              height: '100%',
              color: colors.text.secondary,
            }}
          >
            <Typography variant="body2">
              No output available. Start a scan to see results here.
            </Typography>
          </Box>
        )}
      </Box>
    </Paper>
  );
};

export default TerminalOutput;