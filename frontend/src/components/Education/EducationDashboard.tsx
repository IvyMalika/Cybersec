import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Grid,
  Chip,
  LinearProgress,
  IconButton,
  Tooltip,
  alpha,
  Avatar,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemAvatar,
} from '@mui/material';
import {
  School as SchoolIcon,
  PlayArrow as PlayIcon,
  Assignment as AssignmentIcon,
  Quiz as QuizIcon,
  TrendingUp as TrendingUpIcon,
  Star as StarIcon,
  MoreVert as MoreVertIcon,
  Refresh as RefreshIcon,
  Book as BookIcon,
  VideoLibrary as VideoIcon,
  Assessment as AssessmentIcon,
  WorkspacePremium as CertificateIcon,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { Course, Quiz, Certificate } from '../../types/api';

interface EducationStats {
  totalCourses: number;
  completedCourses: number;
  totalQuizzes: number;
  passedQuizzes: number;
  certificatesEarned: number;
  averageScore: number;
}

const EducationDashboard: React.FC = () => {
  const navigate = useNavigate();
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  const {
    data: courses,
    isLoading: coursesLoading,
    error: coursesError,
  } = useQuery({
    queryKey: ['courses'],
    queryFn: () => apiClient.getCourses(),
  });

  const {
    data: quizzes,
    isLoading: quizzesLoading,
    error: quizzesError,
  } = useQuery({
    queryKey: ['quizzes'],
    queryFn: () => apiClient.getQuizzes(),
  });

  const {
    data: certificates,
    isLoading: certificatesLoading,
    error: certificatesError,
  } = useQuery({
    queryKey: ['certificates'],
    queryFn: () => apiClient.getCertificates(),
  });

  // Mock education statistics
  const educationStats: EducationStats = {
    totalCourses: 24,
    completedCourses: 18,
    totalQuizzes: 36,
    passedQuizzes: 32,
    certificatesEarned: 8,
    averageScore: 87,
  };

  const categories = [
    { value: 'all', label: 'All Courses', color: colors.primary.main },
    { value: 'network', label: 'Network Security', color: colors.accent.blue },
    { value: 'web', label: 'Web Security', color: colors.accent.fuchsia },
    { value: 'malware', label: 'Malware Analysis', color: colors.accent.orange },
    { value: 'forensics', label: 'Digital Forensics', color: colors.accent.teal },
  ];

  const filteredCourses = courses?.filter(course => 
    selectedCategory === 'all' || course.category === selectedCategory
  ) || [];

  const StatCard: React.FC<{
    title: string;
    value: number;
    total?: number;
    icon: React.ReactNode;
    color: string;
    subtitle?: string;
  }> = ({ title, value, total, icon, color, subtitle }) => (
    <Card
      sx={{
        backgroundColor: colors.background.paper,
        border: `1px solid ${colors.border.primary}`,
        borderRadius: 2,
        transition: 'all 0.3s ease-in-out',
        '&:hover': {
          transform: 'translateY(-2px)',
          boxShadow: `0 8px 32px ${alpha(color, 0.2)}`,
        },
      }}
    >
      <CardContent sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 700, color, mb: 0.5 }}>
              {value}
              {total && (
                <Typography component="span" variant="h6" sx={{ color: colors.text.secondary }}>
                  /{total}
                </Typography>
              )}
            </Typography>
            <Typography variant="body2" sx={{ color: colors.text.secondary }}>
              {title}
            </Typography>
            {subtitle && (
              <Typography variant="caption" sx={{ color: colors.text.secondary }}>
                {subtitle}
              </Typography>
            )}
          </Box>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 48,
              height: 48,
              borderRadius: '50%',
              backgroundColor: alpha(color, 0.2),
              color,
            }}
          >
            {icon}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );

  const CourseCard: React.FC<{ course: Course }> = ({ course }) => {
    const progress = (course.completed_lessons / course.total_lessons) * 100;
    const category = categories.find(cat => cat.value === course.category);

    return (
      <Card
        sx={{
          backgroundColor: colors.background.paper,
          border: `1px solid ${colors.border.primary}`,
          borderRadius: 2,
          height: '100%',
          transition: 'all 0.3s ease-in-out',
          cursor: 'pointer',
          '&:hover': {
            transform: 'translateY(-4px)',
            boxShadow: `0 8px 32px ${alpha(category?.color || colors.primary.main, 0.2)}`,
          },
        }}
        onClick={() => navigate(`/education/courses/${course.id}`)}
      >
        <CardContent sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <Avatar
                sx={{
                  backgroundColor: alpha(category?.color || colors.primary.main, 0.2),
                  color: category?.color || colors.primary.main,
                  mr: 2,
                }}
              >
                {course.category === 'network' ? <SchoolIcon /> :
                 course.category === 'web' ? <AssignmentIcon /> :
                 course.category === 'malware' ? <AssessmentIcon /> :
                 <BookIcon />}
              </Avatar>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
                  {course.title}
                </Typography>
                <Typography variant="body2" sx={{ color: colors.text.secondary }}>
                  {course.instructor}
                </Typography>
              </Box>
            </Box>
            <IconButton size="small">
              <MoreVertIcon sx={{ color: colors.text.secondary }} />
            </IconButton>
          </Box>

          <Typography variant="body2" sx={{ color: colors.text.secondary, mb: 2, lineHeight: 1.6 }}>
            {course.description}
          </Typography>

          <Box sx={{ mb: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
              <Typography variant="caption" sx={{ color: colors.text.secondary }}>
                Progress
              </Typography>
              <Typography variant="caption" sx={{ color: colors.text.primary, fontWeight: 600 }}>
                {Math.round(progress)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progress}
              sx={{
                height: 6,
                borderRadius: 3,
                backgroundColor: colors.background.elevated,
                '& .MuiLinearProgress-bar': {
                  backgroundColor: category?.color || colors.primary.main,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Chip
                label={category?.label || course.category}
                size="small"
                sx={{
                  backgroundColor: alpha(category?.color || colors.primary.main, 0.2),
                  color: category?.color || colors.primary.main,
                }}
              />
              <Chip
                label={`${course.duration} hours`}
                size="small"
                variant="outlined"
                sx={{
                  borderColor: colors.border.secondary,
                  color: colors.text.secondary,
                }}
              />
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <StarIcon sx={{ color: colors.accent.orange, fontSize: 16 }} />
              <Typography variant="body2" sx={{ color: colors.text.primary }}>
                {course.rating}
              </Typography>
            </Box>
          </Box>
        </CardContent>
      </Card>
    );
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 700, color: colors.text.primary }}>
          Education Dashboard
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh">
            <IconButton
              onClick={() => window.location.reload()}
              sx={{
                backgroundColor: alpha(colors.primary.main, 0.1),
                '&:hover': {
                  backgroundColor: alpha(colors.primary.main, 0.2),
                },
              }}
            >
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Education Statistics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Courses Completed"
            value={educationStats.completedCourses}
            total={educationStats.totalCourses}
            icon={<BookIcon />}
            color={colors.primary.main}
            subtitle="Learning Progress"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Quizzes Passed"
            value={educationStats.passedQuizzes}
            total={educationStats.totalQuizzes}
            icon={<QuizIcon />}
            color={colors.accent.fuchsia}
            subtitle="Knowledge Assessment"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Certificates"
            value={educationStats.certificatesEarned}
            icon={<CertificateIcon />}
            color={colors.accent.teal}
            subtitle="Achievements Earned"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Average Score"
            value={educationStats.averageScore}
            icon={<TrendingUpIcon />}
            color={colors.accent.orange}
            subtitle="Performance"
          />
        </Grid>
      </Grid>

      {/* Category Filter */}
      <Card
        sx={{
          backgroundColor: colors.background.paper,
          border: `1px solid ${colors.border.primary}`,
          borderRadius: 2,
          mb: 4,
        }}
      >
        <CardContent sx={{ p: 2 }}>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            {categories.map((category) => (
              <Chip
                key={category.value}
                label={category.label}
                onClick={() => setSelectedCategory(category.value)}
                sx={{
                  backgroundColor: selectedCategory === category.value 
                    ? category.color 
                    : alpha(category.color, 0.1),
                  color: selectedCategory === category.value 
                    ? colors.text.primary 
                    : category.color,
                  '&:hover': {
                    backgroundColor: alpha(category.color, 0.2),
                  },
                }}
              />
            ))}
          </Box>
        </CardContent>
      </Card>

      {/* Course Grid */}
      <Grid container spacing={3}>
        {filteredCourses.map((course) => (
          <Grid item xs={12} sm={6} md={4} key={course.id}>
            <CourseCard course={course} />
          </Grid>
        ))}
      </Grid>

      {/* Recent Activity */}
      <Card
        sx={{
          backgroundColor: colors.background.paper,
          border: `1px solid ${colors.border.primary}`,
          borderRadius: 2,
          mt: 4,
        }}
      >
        <CardContent sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 600, mb: 3, color: colors.text.primary }}>
            Recent Activity
          </Typography>

          <List>
            {[
              { type: 'course', title: 'Completed Network Security Fundamentals', time: '2 hours ago', icon: <BookIcon /> },
              { type: 'quiz', title: 'Passed Web Security Quiz', time: '1 day ago', icon: <QuizIcon /> },
              { type: 'certificate', title: 'Earned Malware Analysis Certificate', time: '3 days ago', icon: <CertificateIcon /> },
              { type: 'course', title: 'Started Digital Forensics Course', time: '1 week ago', icon: <PlayIcon /> },
            ].map((activity, index) => (
              <ListItem key={index} sx={{ py: 1 }}>
                <ListItemAvatar>
                  <Avatar
                    sx={{
                      backgroundColor: alpha(colors.primary.main, 0.2),
                      color: colors.primary.main,
                    }}
                  >
                    {activity.icon}
                  </Avatar>
                </ListItemAvatar>
                <ListItemText
                  primary={activity.title}
                  secondary={activity.time}
                  primaryTypographyProps={{
                    color: colors.text.primary,
                    fontWeight: 500,
                  }}
                  secondaryTypographyProps={{
                    color: colors.text.secondary,
                  }}
                />
              </ListItem>
            ))}
          </List>
        </CardContent>
      </Card>
    </Box>
  );
};

export default EducationDashboard; 