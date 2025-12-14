// Load environment variables
require('dotenv').config();

const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const methodOverride = require('method-override');
const ejsMate = require('ejs-mate');
const passport = require('passport');
const session = require('express-session');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const flash = require('connect-flash');

const app = express();
const port = process.env.PORT || 8080;

// Security and performance middlewares
app.use(helmet({
  crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use(limiter);

// MySQL Connection setup with environment variables
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

connection.connect(err => {
  if (err) {
    console.error('MySQL connection error:', err);
    process.exit(1);
  }
  console.log('Connected to MySQL database');
});

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'default-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Passport initialization
require('./config/passport')(passport);
app.use(passport.initialize());
app.use(passport.session());

// Flash messages middleware
app.use(flash());

// Middleware
app.engine('ejs', ejsMate);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('view cache', false);
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(methodOverride('_method'));

// Authentication middleware
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// Helper function to get attending event ids
const getAttendingEventIds = (userId) => {
  return new Promise((resolve, reject) => {
    connection.query('SELECT EVENT_ID FROM ATTENDEE WHERE USER_ID = ?', [userId], (err, results) => {
      if (err) reject(err);
      resolve(results.map(r => r.EVENT_ID));
    });
  });
};

// Redirect root to events or dashboard based on user role
app.get('/', (req, res) => {
  if (req.user && req.user.ROLE === 'admin') {
    res.redirect('/admin');
  } else if (req.user && req.user.ROLE === 'organizer') {
    res.redirect('/dashboard');
  } else {
    res.render('index.ejs');
  }
});

// Auth routes
app.get('/login', (req, res) => {
  const errorMessages = req.flash('error');
  const message = errorMessages.length > 0 ? errorMessages[0] : null;
  res.render('login', { message });
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, email, password, role } = req.body;
  if (!['attendee', 'organizer', 'admin'].includes(role)) {
    return res.render('register', { error: 'Invalid role selected' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const sql = 'INSERT INTO USER (USERNAME, EMAIL, PASSWORD_HASH, ROLE) VALUES (?, ?, ?, ?)';
    connection.query(sql, [username, email, hashedPassword, role], (err) => {
      if (err) {
        console.error(err);
        return res.render('register', { error: 'Registration failed' });
      }
      res.redirect('/login');
    });
  } catch (error) {
    res.render('register', { error: 'Registration failed' });
  }
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/events',
  failureRedirect: '/login',
  failureFlash: true
}));

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect('/');
  });
});

// EVENTS ROUTES

// List all events
app.get('/events', async (req, res) => {
  try {
    let sql = `
      SELECT
        e.*,
        c.CATEGORY_NAME
      FROM EVENT e
      LEFT JOIN CATEGORY c ON e.CATEGORY_ID = c.CATEGORY_ID
      WHERE 1=1
    `;
    let params = [];
    let conditions = [];

    // User-based filtering
    if (req.user && req.user.ROLE === 'attendee') {
      conditions.push('STATUS = ?');
      params.push('published');
    } else if (req.user && req.user.ROLE === 'organizer') {
      conditions.push('(ORGANIZER_ID = ? OR STATUS IN (?, ?, ?))');
      params.push(req.user.USER_ID, 'draft', 'published', 'cancelled');
    } else {
      // For non-logged-in users, only show published events
      conditions.push('STATUS = ?');
      params.push('published');
    }

    // Search functionality
    if (req.query.search && req.query.search.trim()) {
      conditions.push('(e.EVENT_NAME LIKE ? OR e.DESCRIPTION LIKE ?)');
      const searchTerm = `%${req.query.search.trim()}%`;
      params.push(searchTerm, searchTerm);
      console.log('Search query:', req.query.search.trim());
      console.log('Search term:', searchTerm);
    }

    // Filter by date
    if (req.query.filter === 'upcoming') {
      conditions.push('EVENT_DATE >= CURDATE()');
    } else if (req.query.filter === 'past') {
      conditions.push('EVENT_DATE < CURDATE()');
    }

    // Filter by category
    if (req.query.category && req.query.category !== '') {
      conditions.push('e.CATEGORY_ID = ?');
      params.push(req.query.category);
    }

    // Apply conditions to SQL
    if (conditions.length > 0) {
      sql += ' AND ' + conditions.join(' AND ');
    }

    // Sort order - default to ascending (oldest first)
    const sortOrder = req.query.sort === 'desc' ? 'DESC' : 'ASC';
    sql += ` ORDER BY e.CREATED_AT ${sortOrder}`;

    const [events] = await connection.promise().query(sql, params);
    let attendingEvents = [];
    if (req.user) {
      attendingEvents = await getAttendingEventIds(req.user.USER_ID);
    }

    // Pass search and filter values to template for form persistence
    res.render('events', {
      events,
      user: req.user,
      attendingEvents,
      searchQuery: req.query.search || '',
      activeFilter: req.query.filter || '',
      activeCategory: req.query.category || '',
      activeSort: req.query.sort || 'asc'
    });
  } catch (err) {
    console.error('Error fetching events:', err);
    res.send('Error fetching events');
  }
});

// New event form
app.get('/events/new', ensureAuthenticated, (req, res) => {
  res.render('form', { entity: 'Event', action: '/events', event: {}, user: req.user });
});

// Create event
app.post('/events', ensureAuthenticated, (req, res) => {
  const { eventname, eventdate, location, description, category, tags } = req.body;
  const userId = req.user.USER_ID;

  // Insert event
  const sql = 'INSERT INTO EVENT (EVENT_NAME, EVENT_DATE, LOCATION, DESCRIPTION, ORGANIZER_ID, CATEGORY_ID, STATUS) VALUES (?, ?, ?, ?, ?, ?, ?)';
  connection.query(sql, [eventname, eventdate, location, description, userId, category || null, 'draft'], (err, result) => {
    if (err) return res.send('Error creating event');

    const eventId = result.insertId;

    // Handle tags if provided (split comma-separated string)
    if (tags && typeof tags === 'string' && tags.trim()) {
      const tagNames = tags.split(',').map(tag => tag.trim()).filter(tag => tag.length > 0);

      if (tagNames.length > 0) {
        const tagPromises = tagNames.map(tagName => {
          return new Promise((resolve, reject) => {
            // First, try to find existing tag or create new one
            connection.query('INSERT IGNORE INTO TAG (TAG_NAME) VALUES (?)', [tagName], (err) => {
              if (err) return reject(err);

              // Get tag ID
              connection.query('SELECT TAG_ID FROM TAG WHERE TAG_NAME = ?', [tagName], (err, tagResults) => {
                if (err) return reject(err);

                if (tagResults.length > 0) {
                  // Link event to tag
                  connection.query('INSERT IGNORE INTO EVENT_TAG (EVENT_ID, TAG_ID) VALUES (?, ?)',
                    [eventId, tagResults[0].TAG_ID], (err) => {
                    if (err) reject(err);
                    else resolve();
                  });
                } else {
                  resolve();
                }
              });
            });
          });
        });

        Promise.all(tagPromises).then(() => {
          res.redirect('/events');
        }).catch(err => {
          console.error('Error saving tags:', err);
          res.redirect('/events');
        });
      } else {
        res.redirect('/events');
      }
    } else {
      res.redirect('/events');
    }
  });
});

// Edit event form
app.get('/events/:id/edit', ensureAuthenticated, (req, res) => {
  connection.query('SELECT * FROM EVENT WHERE EVENT_ID = ?', [req.params.id], (err, events) => {
    if (err || events.length === 0) return res.send('Event not found');
    const event = events[0];
    if (event.ORGANIZER_ID !== req.user.USER_ID) return res.send('Unauthorized');
    res.render('form', { entity: 'Event', action: `/events/${req.params.id}?_method=PUT`, event, user: req.user });
  });
});

// Update event
app.put('/events/:id', ensureAuthenticated, (req, res) => {
  connection.query('SELECT ORGANIZER_ID FROM EVENT WHERE EVENT_ID = ?', [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.send('Event not found');
    if (results[0].ORGANIZER_ID !== req.user.USER_ID) return res.send('Unauthorized');
    const { eventname, eventdate, location, description } = req.body;
    const sql = 'UPDATE EVENT SET EVENT_NAME=?, EVENT_DATE=?, LOCATION=?, DESCRIPTION=? WHERE EVENT_ID=?';
    connection.query(sql, [eventname, eventdate, location, description, req.params.id], err => {
      if (err) return res.send('Error updating event');
      res.redirect('/events');
    });
  });
});

// Delete event
app.delete('/events/:id', ensureAuthenticated, (req, res) => {
  connection.query('SELECT ORGANIZER_ID FROM EVENT WHERE EVENT_ID = ?', [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.send('Event not found');
    if (results[0].ORGANIZER_ID !== req.user.USER_ID) return res.send('Unauthorized');
    connection.query('DELETE FROM EVENT WHERE EVENT_ID = ?', [req.params.id], err => {
      if (err) return res.send('Error deleting event');
      res.redirect('/events');
    });
  });
});

// Event status management routes
app.post('/events/:id/publish', ensureAuthenticated, (req, res) => {
  connection.query('SELECT ORGANIZER_ID FROM EVENT WHERE EVENT_ID = ?', [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.send('Event not found');
    if (results[0].ORGANIZER_ID !== req.user.USER_ID) return res.send('Unauthorized');
    connection.query('UPDATE EVENT SET STATUS = ? WHERE EVENT_ID = ?', ['published', req.params.id], err => {
      if (err) return res.send('Error publishing event');
      res.redirect('/events');
    });
  });
});

app.post('/events/:id/unpublish', ensureAuthenticated, (req, res) => {
  connection.query('SELECT ORGANIZER_ID FROM EVENT WHERE EVENT_ID = ?', [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.send('Event not found');
    if (results[0].ORGANIZER_ID !== req.user.USER_ID) return res.send('Unauthorized');
    connection.query('UPDATE EVENT SET STATUS = ? WHERE EVENT_ID = ?', ['draft', req.params.id], err => {
      if (err) return res.send('Error unpublishing event');
      res.redirect('/events');
    });
  });
});

app.post('/events/:id/cancel', ensureAuthenticated, (req, res) => {
  connection.query('SELECT ORGANIZER_ID FROM EVENT WHERE EVENT_ID = ?', [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.send('Event not found');
    if (results[0].ORGANIZER_ID !== req.user.USER_ID) return res.send('Unauthorized');
    connection.query('UPDATE EVENT SET STATUS = ? WHERE EVENT_ID = ?', ['cancelled', req.params.id], err => {
      if (err) return res.send('Error cancelling event');
      res.redirect('/events');
    });
  });
});

// Join event form
app.get('/events/:id/join', ensureAuthenticated, (req, res) => {
  connection.query('SELECT EVENT_ID, EVENT_NAME FROM EVENT WHERE EVENT_ID = ?', [req.params.id], (err, events) => {
    if (err || events.length === 0) return res.send('Event not found');
    res.render('form', { entity: 'Attendee', action: `/events/${req.params.id}/join`, attendee: {}, events });
  });
});

// Join event
app.post('/events/:id/join', ensureAuthenticated, (req, res) => {
  const { name, email, number } = req.body;
  const eventId = req.params.id;
  const userId = req.user.USER_ID;
  const sql = 'INSERT INTO ATTENDEE (USER_ID, NAME, EMAIL, NUMBER, EVENT_ID, STATUS) VALUES (?, ?, ?, ?, ?, ?)';
  connection.query(sql, [userId, name, email, number, eventId, 'registered'], err => {
    if (err) return res.send('Error joining event');
    res.redirect('/events');
  });
});

// Leave event
app.post('/events/:id/leave', ensureAuthenticated, (req, res) => {
  const eventId = req.params.id;
  const userId = req.user.USER_ID;
  const sql = 'DELETE FROM ATTENDEE WHERE USER_ID = ? AND EVENT_ID = ?';
  connection.query(sql, [userId, eventId], (err, result) => {
    if (err) return res.send('Error leaving event');
    res.redirect('/events');
  });
});

// Show attendees of a particular event
app.get('/events/:id/attendees', (req, res) => {
  const eventId = req.params.id;
  const sqlEvent = 'SELECT * FROM EVENT WHERE EVENT_ID = ?';
  const userId = req.user ? req.user.USER_ID : null;

  connection.query(sqlEvent, [eventId], (err, eventResults) => {
    if (err || eventResults.length === 0) return res.send('Event not found');
    const event = eventResults[0];
    const isOrganizer = req.user && event.ORGANIZER_ID === req.user.USER_ID;
    
    let sqlAttendees = 'SELECT a.*, e.EVENT_NAME FROM ATTENDEE a JOIN EVENT e ON a.EVENT_ID = e.EVENT_ID WHERE a.EVENT_ID = ?';
    let params = [eventId];
    
    if (!isOrganizer) {
      sqlAttendees += ' AND (a.USER_ID = ? OR a.USER_ID IS NULL)';
      params.push(userId);
    }

    connection.query(sqlAttendees, params, (err, attendees) => {
      if (err) return res.send('Error fetching attendees');
      res.render('attendees', { attendees, event: eventResults[0], user: req.user });
    });
  });
});

// ATTENDEES ROUTES

// List all attendees
app.get('/attendees', (req, res) => {
  const sql = `
    SELECT a.*, e.EVENT_NAME
    FROM ATTENDEE a
    JOIN EVENT e ON a.EVENT_ID = e.EVENT_ID
  `;
  connection.query(sql, (err, attendees) => {
    if (err) return res.send('Error fetching attendees');
    res.render('attendees', { attendees, event: null, user: req.user });
  });
});

// New attendee form
app.get('/attendees/new', (req, res) => {
  connection.query('SELECT EVENT_ID, EVENT_NAME FROM EVENT', (err, events) => {
    if (err) return res.send('Error fetching events');
    res.render('form', { entity: 'Attendee', action: '/attendees', attendee: {}, events, user: req.user });
  });
});

// New attendee form for specific event
app.get('/events/:id/attendees/new', (req, res) => {
  const eventId = req.params.id;
  connection.query('SELECT EVENT_ID, EVENT_NAME FROM EVENT WHERE EVENT_ID = ?', [eventId], (err, events) => {
    if (err || events.length === 0) return res.send('Event not found');
    res.render('form', { entity: 'Attendee', action: '/attendees', attendee: { EVENT_ID: eventId }, events, user: req.user });
  });
});

// Create attendee
app.post('/attendees', (req, res) => {
  const { name, email, number, eventid, status } = req.body;
  const userId = req.user ? req.user.USER_ID : null;
  const sql = 'INSERT INTO ATTENDEE (USER_ID, NAME, EMAIL, NUMBER, EVENT_ID, STATUS) VALUES (?, ?, ?, ?, ?, ?)';
  connection.query(sql, [userId, name, email, number, eventid, status || 'registered'], err => {
    if (err) return res.send('Error creating attendee');
    res.redirect(eventid ? `/events/${eventid}/attendees` : '/attendees');
  });
});

// Edit attendee form
app.get('/attendees/:id/edit', ensureAuthenticated, (req, res) => {
  connection.query('SELECT * FROM ATTENDEE WHERE ATTENDEE_ID = ?', [req.params.id], (err, attendees) => {
    if (err || attendees.length === 0) return res.send('Attendee not found');
    const attendee = attendees[0];
    if (attendee.USER_ID !== req.user.USER_ID) return res.send('Unauthorized');
    connection.query('SELECT EVENT_ID, EVENT_NAME FROM EVENT', (err, events) => {
      if (err) return res.send('Error fetching events');
      res.render('form', { entity: 'Attendee', action: `/attendees/${req.params.id}?_method=PUT`, attendee, events, user: req.user });
    });
  });
});

// Update attendee
app.put('/attendees/:id', ensureAuthenticated, (req, res) => {
  connection.query('SELECT USER_ID FROM ATTENDEE WHERE ATTENDEE_ID = ?', [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.send('Attendee not found');
    if (results[0].USER_ID !== req.user.USER_ID) return res.send('Unauthorized');
    const { name, email, number, eventid, status } = req.body;
    const sql = 'UPDATE ATTENDEE SET NAME=?, EMAIL=?, NUMBER=?, EVENT_ID=?, STATUS=? WHERE ATTENDEE_ID=?';
    connection.query(sql, [name, email, number, eventid, status, req.params.id], err => {
      if (err) return res.send('Error updating attendee');
      res.redirect(eventid ? `/events/${eventid}/attendees` : '/attendees');
    });
  });
});

// Delete attendee
app.delete('/attendees/:id', ensureAuthenticated, (req, res) => {
  connection.query('SELECT a.USER_ID, a.EVENT_ID, e.ORGANIZER_ID FROM ATTENDEE a JOIN EVENT e ON a.EVENT_ID = e.EVENT_ID WHERE ATTENDEE_ID = ?', [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.send('Attendee not found');
    const attendee = results[0];
    // Allow if attendee owns registration or if user is the event organizer
    if (attendee.USER_ID !== req.user.USER_ID && attendee.ORGANIZER_ID !== req.user.USER_ID) return res.send('Unauthorized');
    const eventId = attendee.EVENT_ID;
    connection.query('DELETE FROM ATTENDEE WHERE ATTENDEE_ID=?', [req.params.id], err => {
      if (err) return res.send('Error deleting attendee');
      res.redirect(eventId ? `/events/${eventId}/attendees` : '/attendees');
    });
  });
});

// Organizer Dashboard
app.get('/dashboard', ensureAuthenticated, async (req, res) => {
  if (req.user.ROLE !== 'organizer') {
    return res.redirect('/events');
  }

  try {
    const organizerId = req.user.USER_ID;

    // Get total events created
    const [totalEventsResult] = await connection.promise().query(
      'SELECT COUNT(*) as total FROM EVENT WHERE ORGANIZER_ID = ?',
      [organizerId]
    );
    const totalEvents = totalEventsResult[0].total;

    // Get total attendees across all events
    const [totalAttendeesResult] = await connection.promise().query(
      'SELECT COUNT(*) as total FROM ATTENDEE a JOIN EVENT e ON a.EVENT_ID = e.EVENT_ID WHERE e.ORGANIZER_ID = ?',
      [organizerId]
    );
    const totalAttendees = totalAttendeesResult[0].total;

    // Get upcoming events count
    const [upcomingEventsResult] = await connection.promise().query(
      'SELECT COUNT(*) as total FROM EVENT WHERE ORGANIZER_ID = ? AND EVENT_DATE >= CURDATE() AND STATUS != "cancelled"',
      [organizerId]
    );
    const upcomingEvents = upcomingEventsResult[0].total;

    // Get past events count
    const [pastEventsResult] = await connection.promise().query(
      'SELECT COUNT(*) as total FROM EVENT WHERE ORGANIZER_ID = ? AND EVENT_DATE < CURDATE()',
      [organizerId]
    );
    const pastEvents = pastEventsResult[0].total;

    // Get top 3 most registered events
    const [topEventsResult] = await connection.promise().query(`
      SELECT
        e.EVENT_NAME,
        COUNT(a.ATTENDEE_ID) as attendee_count
      FROM EVENT e
      LEFT JOIN ATTENDEE a ON e.EVENT_ID = a.EVENT_ID
      WHERE e.ORGANIZER_ID = ?
      GROUP BY e.EVENT_ID, e.EVENT_NAME
      ORDER BY attendee_count DESC
      LIMIT 3
    `, [organizerId]);

    const stats = {
      totalEvents,
      totalAttendees,
      upcomingEvents,
      pastEvents,
      topEvents: topEventsResult
    };

    res.render('dashboard', { user: req.user, stats });
  } catch (err) {
    console.error('Error fetching dashboard stats:', err);
    res.send('Error loading dashboard');
  }
});

// Admin Dashboard
app.get('/admin', ensureAuthenticated, async (req, res) => {
  if (req.user.ROLE !== 'admin') {
    return res.redirect('/events');
  }

  try {
    // Get system-wide statistics
    const [totalUsersResult] = await connection.promise().query('SELECT COUNT(*) as total FROM USER');
    const totalUsers = totalUsersResult[0].total;

    const [totalEventsResult] = await connection.promise().query('SELECT COUNT(*) as total FROM EVENT');
    const totalEvents = totalEventsResult[0].total;

    const [totalAttendeesResult] = await connection.promise().query('SELECT COUNT(*) as total FROM ATTENDEE');
    const totalAttendees = totalAttendeesResult[0].total;

    // Get user distribution by role
    const [userRolesResult] = await connection.promise().query(
      'SELECT ROLE, COUNT(*) as count FROM USER GROUP BY ROLE'
    );

    // Get recent events (last 10)
    const [recentEventsResult] = await connection.promise().query(
      'SELECT e.*, u.USERNAME as ORGANIZER_NAME FROM EVENT e JOIN USER u ON e.ORGANIZER_ID = u.USER_ID ORDER BY e.CREATED_AT DESC LIMIT 10'
    );

    // Get events by status
    const [eventStatusResult] = await connection.promise().query(
      'SELECT STATUS, COUNT(*) as count FROM EVENT GROUP BY STATUS'
    );

    // Get top categories
    const [topCategoriesResult] = await connection.promise().query(`
      SELECT c.CATEGORY_NAME, COUNT(e.EVENT_ID) as event_count
      FROM CATEGORY c
      LEFT JOIN EVENT e ON c.CATEGORY_ID = e.CATEGORY_ID
      GROUP BY c.CATEGORY_ID, c.CATEGORY_NAME
      ORDER BY event_count DESC
      LIMIT 5
    `);

    const stats = {
      totalUsers,
      totalEvents,
      totalAttendees,
      userRoles: userRolesResult,
      recentEvents: recentEventsResult,
      eventStatus: eventStatusResult,
      topCategories: topCategoriesResult
    };

    res.render('admin', { user: req.user, stats });
  } catch (err) {
    console.error('Error fetching admin stats:', err);
    res.send('Error loading admin dashboard');
  }
});

// Admin Routes for Management
app.get('/admin/users', ensureAuthenticated, async (req, res) => {
  if (req.user.ROLE !== 'admin') return res.redirect('/events');

  try {
    const [users] = await connection.promise().query(
      'SELECT USER_ID, USERNAME, EMAIL, ROLE, CREATED_AT FROM USER ORDER BY CREATED_AT DESC'
    );
    res.render('admin-users', { user: req.user, users });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.send('Error loading users');
  }
});

app.get('/admin/events', ensureAuthenticated, async (req, res) => {
  if (req.user.ROLE !== 'admin') return res.redirect('/events');

  try {
    const [events] = await connection.promise().query(`
      SELECT e.*, u.USERNAME as ORGANIZER_NAME, c.CATEGORY_NAME
      FROM EVENT e
      JOIN USER u ON e.ORGANIZER_ID = u.USER_ID
      LEFT JOIN CATEGORY c ON e.CATEGORY_ID = c.CATEGORY_ID
      ORDER BY e.CREATED_AT DESC
    `);
    res.render('admin-events', { user: req.user, events });
  } catch (err) {
    console.error('Error fetching events:', err);
    res.send('Error loading events');
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server started at http://localhost:${port}`);
});
