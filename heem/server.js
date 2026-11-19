const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.sqlite');

// 1. إنشاء وتهيئة قاعدة البيانات
const db = new DatabaseSync(DB_FILE);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_type TEXT NOT NULL,
    identifier TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    membership_type TEXT,
    org_cr TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS identity_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_identifier TEXT NOT NULL,
    full_name TEXT NOT NULL,
    phone TEXT,
    email TEXT,
    birth_date TEXT,
    gender TEXT,
    nationality TEXT,
    halfaia_relation TEXT,
    id_doc_name TEXT,
    photo_name TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// التأكد من وجود عمود role في جدول المستخدمين
try {
  db.exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'");
} catch (e) {
  // العمود موجود مسبقاً
}
try {
  db.exec("ALTER TABLE users ADD COLUMN org_service TEXT");
} catch (e) {}

// التأكد من وجود أعمدة بيانات المستندات والصور في جدول طلبات الهوية
try {
  db.exec("ALTER TABLE identity_requests ADD COLUMN id_doc_data TEXT");
} catch (e) {}
try {
  db.exec("ALTER TABLE identity_requests ADD COLUMN photo_data TEXT");
} catch (e) {}

// إنشاء جداول المنظومة الطبية والمراكز الصحية
db.exec(`
  CREATE TABLE IF NOT EXISTS medical_appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_num TEXT UNIQUE,
    patient_name TEXT,
    patient_phone TEXT,
    center_name TEXT,
    clinic TEXT,
    doctor TEXT,
    appointment_date TEXT,
    time_slot TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS medical_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_identifier TEXT,
    mrn TEXT UNIQUE,
    full_name TEXT,
    national_id TEXT,
    phone TEXT,
    blood_type TEXT,
    chronic_diseases TEXT,
    allergies TEXT,
    emergency_contact TEXT,
    emergency_phone TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS medical_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_name TEXT,
    mrn TEXT,
    test_type TEXT,
    test_date TEXT,
    status TEXT DEFAULT 'جاهز',
    summary TEXT,
    doctor_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS medical_consultations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_identifier TEXT,
    patient_name TEXT,
    phone TEXT,
    specialty TEXT,
    urgency TEXT,
    symptoms TEXT,
    doctor_reply TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS medical_center_info (
    id INTEGER PRIMARY KEY,
    name TEXT,
    address TEXT,
    hours TEXT,
    emergency TEXT,
    phone TEXT,
    is_open INTEGER DEFAULT 1,
    status_text TEXT
  );

  CREATE TABLE IF NOT EXISTS medical_clinics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    doctor TEXT,
    time_schedule TEXT,
    icon TEXT,
    status TEXT DEFAULT 'متاحة الآن',
    is_er INTEGER DEFAULT 0,
    max_patients INTEGER DEFAULT 20,
    start_time TEXT DEFAULT '09:00',
    end_time TEXT DEFAULT '14:00',
    work_days TEXT DEFAULT 'السبت - الخميس'
  );
`);

try { db.exec("ALTER TABLE medical_clinics ADD COLUMN max_patients INTEGER DEFAULT 20"); } catch (e) {}
try { db.exec("ALTER TABLE medical_clinics ADD COLUMN start_time TEXT DEFAULT '09:00'"); } catch (e) {}
try { db.exec("ALTER TABLE medical_clinics ADD COLUMN end_time TEXT DEFAULT '14:00'"); } catch (e) {}
try { db.exec("ALTER TABLE medical_clinics ADD COLUMN work_days TEXT DEFAULT 'السبت - الخميس'"); } catch (e) {}
try { db.exec("ALTER TABLE medical_appointments ADD COLUMN has_medical_file INTEGER DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE medical_appointments ADD COLUMN mrn TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE medical_files ADD COLUMN center_name TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE medical_files ADD COLUMN booking_num TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE medical_results ADD COLUMN result_image TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE medical_results ADD COLUMN booking_num TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE medical_results ADD COLUMN center_name TEXT"); } catch (e) {}

console.log('✅ تم تهيئة قاعدة البيانات المحلية بنجاح في:', DB_FILE);

// دوال تشفير كلمات المرور وحمايتها
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

// دالة مساعدة لقراءة جسم الطلب (JSON Body)
function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 50e6) req.socket.destroy(); // حماية مع دعم رفع المستندات والصور
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

// إرسال رد JSON مع تفعيل CORS
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(JSON.stringify(data));
}

// إرسال الملفات الثابتة (HTML, CSS, JS)
function serveStaticFile(res, filePath, contentType = 'text/html; charset=utf-8') {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('الملف غير موجود');
    } else {
      res.writeHead(200, {
        'Content-Type': contentType,
        'Access-Control-Allow-Origin': '*'
      });
      res.end(data);
    }
  });
}

// 2. إنشاء السيرفر واستقبال الطلبات
const server = http.createServer(async (req, res) => {
  // معالجة طلبات Preflight لـ CORS
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  // المسار 1: تسجيل حساب جديد (API Register)
  if (req.method === 'POST' && url.pathname === '/api/register') {
    try {
      const data = await parseJsonBody(req);
      const isIndividual = data.accountType === 'individual';
      const identifier = (isIndividual ? data.username : data.orgName || '').trim();
      const email = (isIndividual ? data.email : data.orgEmail || '').trim();
      const phone = (isIndividual ? data.phone : data.orgPhone || '').trim();
      const password = data.password || '';
      const membershipType = isIndividual ? (data.membershipType || null) : null;
      const orgCr = !isIndividual ? (data.orgCr || null) : null;
      const orgService = !isIndividual ? (data.orgService || null) : null;

      if (!identifier || !email || !password) {
        return sendJson(res, 400, { ok: false, message: 'يرجى إكمال جميع الحقول الإلزامية.' });
      }

      // التحقق من تكرار اسم المستخدم أو البريد في قاعدة البيانات
      const checkStmt = db.prepare('SELECT id FROM users WHERE LOWER(identifier) = LOWER(?) OR LOWER(email) = LOWER(?) LIMIT 1');
      const existing = checkStmt.get(identifier, email);

      if (existing) {
        return sendJson(res, 409, { ok: false, message: 'اسم المستخدم أو البريد الإلكتروني مسجل مسبقًا في قاعدة البيانات.' });
      }

      // تشفير كلمة المرور وحفظ الحساب
      const { salt, hash } = hashPassword(password);
      const insertStmt = db.prepare(`
        INSERT INTO users (account_type, identifier, email, phone, password_hash, salt, membership_type, org_cr, org_service)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      insertStmt.run(data.accountType, identifier, email, phone, hash, salt, membershipType, orgCr, orgService);

      console.log(`👤 تم تسجيل حساب جديد في قاعدة البيانات: [${data.accountType}] ${identifier}`);
      return sendJson(res, 201, { ok: true, message: 'تم حفظ الحساب بنجاح في قاعدة البيانات!' });

    } catch (err) {
      console.error('خطأ أثناء التسجيل:', err);
      return sendJson(res, 500, { ok: false, message: 'حدث خطأ في الخادم أثناء حفظ البيانات.' });
    }
  }

  // المسار 2: تسجيل الدخول (API Login)
  if (req.method === 'POST' && url.pathname === '/api/login') {
    try {
      const { username, password } = await parseJsonBody(req);

      if (!username || !password) {
        return sendJson(res, 400, { ok: false, message: 'يرجى إدخال اسم المستخدم وكلمة المرور.' });
      }

      // البحث عن المستخدم بالاسم أو البريد الإلكتروني
      const findStmt = db.prepare('SELECT * FROM users WHERE LOWER(identifier) = LOWER(?) OR LOWER(email) = LOWER(?) LIMIT 1');
      const user = findStmt.get(username.trim(), username.trim());

      if (!user) {
        return sendJson(res, 401, { ok: false, message: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });
      }

      // التحقق من صحة كلمة المرور المشفرة
      const isValid = verifyPassword(password, user.salt, user.password_hash);
      if (!isValid) {
        return sendJson(res, 401, { ok: false, message: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });
      }

      console.log(`🔓 تم تسجيل دخول ناجح للمستخدم: ${user.identifier} (${user.account_type})`);
      return sendJson(res, 200, {
        ok: true,
        message: 'تم التحقق من الحساب بنجاح!',
        accountType: user.account_type,
        identifier: user.identifier,
        email: user.email,
        phone: user.phone,
        membershipType: user.membership_type,
        orgService: user.org_service || '',
        role: user.role || (user.identifier.toLowerCase() === 'admin' ? 'admin' : 'user')
      });

    } catch (err) {
      console.error('خطأ أثناء تسجيل الدخول:', err);
      return sendJson(res, 500, { ok: false, message: 'حدث خطأ في الخادم أثناء التحقق.' });
    }
  }

  // المسار 3: حفظ طلب إنشاء هوية رقمية (API Create ID Request)
  if (req.method === 'POST' && url.pathname === '/api/create-id') {
    try {
      const data = await parseJsonBody(req);
      const userIdentifier = (data.userIdentifier || 'anonymous').trim();
      const fullName = (data.fullName || '').trim();
      const phone = (data.phone || '').trim();
      const email = (data.email || '').trim();
      const birthDate = data.birthDate || '';
      const gender = data.gender || '';
      const nationality = data.nationality || '';
      const halfaiaRelation = data.halfaiaRelation || '';
      const idDocName = data.idDocName || '';
      const idDocData = data.idDocData || '';
      const photoName = data.photoName || '';
      const photoData = data.photoData || '';

      if (!fullName || !birthDate || !gender || !nationality) {
        return sendJson(res, 400, { ok: false, message: 'يرجى استيفاء جميع البيانات الإلزامية للطلب.' });
      }

      const insertStmt = db.prepare(`
        INSERT INTO identity_requests (
          user_identifier, full_name, phone, email, birth_date, gender, nationality, halfaia_relation, id_doc_name, id_doc_data, photo_name, photo_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      insertStmt.run(
        userIdentifier, fullName, phone, email, birthDate, gender, nationality, halfaiaRelation, idDocName, idDocData, photoName, photoData
      );

      console.log(`🪪 تم تسجيل طلب هوية رقمية جديد للمستخدم: ${userIdentifier} (${fullName})`);
      return sendJson(res, 201, { ok: true, message: 'تم إرسال طلب إنشاء الهوية الرقمية بنجاح!' });

    } catch (err) {
      console.error('خطأ أثناء حفظ طلب الهوية:', err);
      return sendJson(res, 500, { ok: false, message: 'حدث خطأ في الخادم أثناء حفظ الطلب.' });
    }
  }

  // المسار 4: استعراض الحسابات المسجلة للتحقق (API Users - دون كلمات المرور)
  if (req.method === 'GET' && url.pathname === '/api/users') {
    const listStmt = db.prepare('SELECT id, account_type, identifier, email, phone, membership_type, org_cr, org_service, role, created_at FROM users ORDER BY id DESC');
    const users = listStmt.all();
    return sendJson(res, 200, { count: users.length, users });
  }

  // المسار 5: استعراض طلبات الهوية الرقمية (API ID Requests)
  if (req.method === 'GET' && url.pathname === '/api/id-requests') {
    const reqStmt = db.prepare('SELECT * FROM identity_requests ORDER BY id DESC');
    const requests = reqStmt.all();
    return sendJson(res, 200, { count: requests.length, requests });
  }

  // المسار 5 ب: جلب حالة وبيانات الهوية الرقمية للمستخدم الحالي (API My Identity)
  if (req.method === 'GET' && url.pathname === '/api/my-identity') {
    const userIdentifier = (url.searchParams.get('userIdentifier') || '').trim();
    if (!userIdentifier) {
      return sendJson(res, 400, { ok: false, message: 'معرف المستخدم مطلوب.' });
    }

    const stmt = db.prepare(`
      SELECT * FROM identity_requests 
      WHERE LOWER(user_identifier) = LOWER(?) 
      ORDER BY id DESC LIMIT 1
    `);
    const reqRow = stmt.get(userIdentifier);

    if (!reqRow) {
      return sendJson(res, 200, {
        ok: true,
        hasRequest: false,
        status: 'none',
        approved: false,
        identity: null
      });
    }

    return sendJson(res, 200, {
      ok: true,
      hasRequest: true,
      status: reqRow.status || 'pending',
      approved: reqRow.status === 'approved',
      identity: reqRow
    });
  }

  // المسار 6: تحديث حالة طلب الهوية (قبول / رفض)
  if (req.method === 'POST' && url.pathname === '/api/id-requests/status') {
    try {
      const { id, status } = await parseJsonBody(req);
      if (!id || !status) return sendJson(res, 400, { ok: false, message: 'بيانات غير مكتملة.' });
      const updateStmt = db.prepare('UPDATE identity_requests SET status = ? WHERE id = ?');
      updateStmt.run(status, id);
      console.log(`📌 تم تحديث حالة طلب الهوية رقم ${id} إلى: ${status}`);
      return sendJson(res, 200, { ok: true, message: 'تم تحديث حالة الطلب بنجاح.' });
    } catch (err) {
      console.error('Error updating status:', err);
      return sendJson(res, 500, { ok: false, message: 'حدث خطأ في الخادم.' });
    }
  }

  // المسار 7: تعديل رتبة المستخدم (ترقية إلى مسؤول أو عضو)
  if (req.method === 'POST' && url.pathname === '/api/users/role') {
    try {
      const { identifier, role } = await parseJsonBody(req);
      if (!identifier || !role) return sendJson(res, 400, { ok: false, message: 'بيانات غير مكتملة.' });
      const updateStmt = db.prepare('UPDATE users SET role = ? WHERE identifier = ?');
      updateStmt.run(role, identifier);
      console.log(`👑 تم تعديل صلاحية المستخدم ${identifier} إلى: ${role}`);
      return sendJson(res, 200, { ok: true, message: 'تم تعديل الرتبة بنجاح.' });
    } catch (err) {
      console.error('Error updating role:', err);
      return sendJson(res, 500, { ok: false, message: 'حدث خطأ في الخادم.' });
    }
  }

  // المسار 8: حذف مستخدم من قاعدة البيانات
  if (req.method === 'POST' && url.pathname === '/api/users/delete') {
    try {
      const { identifier } = await parseJsonBody(req);
      if (!identifier) return sendJson(res, 400, { ok: false, message: 'اسم المستخدم مطلوب.' });
      const delStmt = db.prepare('DELETE FROM users WHERE identifier = ?');
      delStmt.run(identifier);
      console.log(`🗑️ تم حذف المستخدم ${identifier} من قاعدة البيانات.`);
      return sendJson(res, 200, { ok: true, message: 'تم حذف المستخدم بنجاح.' });
    } catch (err) {
      console.error('Error deleting user:', err);
      return sendJson(res, 500, { ok: false, message: 'حدث خطأ في الخادم.' });
    }
  }

  // ════════ مسارات النظام الطبي والمراكز الصحية (Medical System APIs) ════════

  // 1. جلب المواعيد الطبية
  if (req.method === 'GET' && url.pathname === '/api/medical/appointments') {
    const list = db.prepare('SELECT * FROM medical_appointments ORDER BY id DESC').all();
    return sendJson(res, 200, { ok: true, appointments: list });
  }

  // 2. حجز موعد جديد أو تحديث حالة الموعد أو حذفه
  if (req.method === 'POST' && (url.pathname === '/api/medical/appointments' || url.pathname === '/api/medical/appointments/delete')) {
    try {
      const data = await parseJsonBody(req);
      if (data.action === 'delete' || url.pathname === '/api/medical/appointments/delete') {
        db.prepare('DELETE FROM medical_appointments WHERE id = ?').run(data.id);
        return sendJson(res, 200, { ok: true, message: 'تم حذف الموعد بنجاح.' });
      }
      if (data.action === 'update_status') {
        const stmt = db.prepare('UPDATE medical_appointments SET status = ? WHERE id = ?');
        stmt.run(data.status, data.id);
        return sendJson(res, 200, { ok: true, message: 'تم تحديث حالة الموعد.' });
      }
      const bookingNum = data.bookingNum || data.booking_num || ('BK-HAL-' + Math.floor(1000 + Math.random() * 9000));
      const stmt = db.prepare(`
        INSERT INTO medical_appointments (booking_num, patient_name, patient_phone, center_name, clinic, doctor, appointment_date, time_slot, status, has_medical_file, mrn)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        bookingNum,
        data.patientName || data.patient_name || 'مواطن',
        data.patientPhone || data.patient_phone || '',
        data.centerName || data.center_name || 'مركز صحي حلفاية الملوك النموذجي',
        data.clinic || 'العيادة العامة',
        data.doctor || 'طبيب مناوب',
        data.appointmentDate || data.appointment_date || new Date().toISOString().split('T')[0],
        data.timeSlot || data.time_slot || '10:00 ص',
        data.status || 'pending',
        data.has_medical_file ? 1 : 0,
        data.mrn || ''
      );
      return sendJson(res, 201, { ok: true, bookingNum, message: 'تم حفظ الموعد بنجاح!' });
    } catch (err) {
      console.error('Error saving appointment:', err);
      return sendJson(res, 500, { ok: false, message: 'فشل حفظ الموعد.' });
    }
  }

  // 3. جلب وحفظ الملفات الطبية الموحدة
  if (req.method === 'GET' && url.pathname === '/api/medical/files') {
    const centerParam = url.searchParams.get('center');
    const userParam = url.searchParams.get('user') || url.searchParams.get('userIdentifier');
    let files;
    if (userParam) {
      files = db.prepare("SELECT * FROM medical_files WHERE user_identifier = ? ORDER BY id DESC").all(userParam);
    } else if (centerParam) {
      files = db.prepare("SELECT * FROM medical_files WHERE center_name = ? OR center_name IS NULL OR center_name = '' ORDER BY id DESC").all(centerParam);
    } else {
      files = db.prepare('SELECT * FROM medical_files ORDER BY id DESC').all();
    }
    return sendJson(res, 200, { ok: true, files });
  }

  if (req.method === 'POST' && url.pathname === '/api/medical/files') {
    try {
      const d = await parseJsonBody(req);
      const mrn = d.mrn || ('MRN-HAL-' + Math.floor(10000 + Math.random() * 90000));
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO medical_files (user_identifier, mrn, full_name, national_id, phone, blood_type, chronic_diseases, allergies, emergency_contact, emergency_phone, center_name, booking_num)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        d.userIdentifier || d.user_identifier || '',
        mrn,
        d.fullName || d.full_name || d.name || '',
        d.nationalId || d.national_id || d.natId || '',
        d.phone || '',
        d.bloodType || d.blood_type || d.blood || 'غير محدد',
        d.chronicDiseases || d.chronic_diseases || d.chronic || 'لا يوجد',
        d.allergies || 'لا يوجد',
        d.emergencyContact || d.emergency_contact || d.emg || '',
        d.emergencyPhone || d.emergency_phone || '',
        d.centerName || d.center_name || '',
        d.bookingNum || d.booking_num || ''
      );
      return sendJson(res, 201, { ok: true, mrn, message: 'تم إرسال الملف الطبي بنجاح للمركز!' });
    } catch (err) {
      console.error('Error saving medical file:', err);
      return sendJson(res, 500, { ok: false, message: 'فشل حفظ الملف الطبي.' });
    }
  }

  // 4. جلب وإصدار نتائج الفحوصات والمختبر
  if (req.method === 'GET' && url.pathname === '/api/medical/results') {
    const results = db.prepare('SELECT * FROM medical_results ORDER BY id DESC').all();
    return sendJson(res, 200, { ok: true, results });
  }

  if (req.method === 'POST' && url.pathname === '/api/medical/results') {
    try {
      const d = await parseJsonBody(req);
      const patName = d.patient_name || d.patientName || '';
      const mrnVal = d.mrn || '';
      const testType = d.test_type || d.testType || 'فحص شامل';
      const testDate = d.test_date || d.testDate || new Date().toISOString().split('T')[0];
      const status = d.status || 'جاهز';
      const summary = d.summary || 'النتائج ضمن الحدود الطبيعية';
      const docName = d.doctor_name || d.doctorName || 'د. استشاري المختبر';
      const resImg = d.result_image || d.resultImage || '';
      const bNum = d.booking_num || d.bookingNum || '';
      const cName = d.center_name || d.centerName || '';

      if (d.id) {
        const existing = db.prepare('SELECT * FROM medical_results WHERE id = ?').get(d.id);
        if (existing) {
          db.prepare(`
            UPDATE medical_results 
            SET patient_name = ?, mrn = ?, test_type = ?, test_date = ?, status = ?, summary = ?, doctor_name = ?, result_image = ?, booking_num = ?, center_name = ?
            WHERE id = ?
          `).run(patName, mrnVal, testType, testDate, status, summary, docName, resImg, bNum, cName, d.id);
          return sendJson(res, 200, { ok: true, message: 'تم تحديث نتيجة الفحص بنجاح!' });
        }
      }

      const stmt = db.prepare(`
        INSERT INTO medical_results (patient_name, mrn, test_type, test_date, status, summary, doctor_name, result_image, booking_num, center_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(patName, mrnVal, testType, testDate, status, summary, docName, resImg, bNum, cName);
      return sendJson(res, 201, { ok: true, message: 'تم حفظ وإصدار نتيجة الفحص بنجاح!' });
    } catch (err) {
      console.error('Error saving lab result:', err);
      return sendJson(res, 500, { ok: false, message: 'فشل حفظ النتيجة.' });
    }
  }

  // 5. الاستشارات الطبية والرد عليها
  if (req.method === 'GET' && url.pathname === '/api/medical/consultations') {
    const list = db.prepare('SELECT * FROM medical_consultations ORDER BY id DESC').all();
    return sendJson(res, 200, { ok: true, consultations: list });
  }

  if (req.method === 'POST' && url.pathname === '/api/medical/consultations') {
    try {
      const d = await parseJsonBody(req);
      if (d.action === 'reply') {
        const stmt = db.prepare('UPDATE medical_consultations SET doctor_reply = ?, status = ? WHERE id = ?');
        stmt.run(d.doctorReply, 'replied', d.id);
        return sendJson(res, 200, { ok: true, message: 'تم إرسال الرد الطبي للمريض.' });
      }
      const stmt = db.prepare(`
        INSERT INTO medical_consultations (user_identifier, patient_name, phone, specialty, urgency, symptoms, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        d.userIdentifier || '',
        d.patientName || '',
        d.phone || '',
        d.specialty || 'الطب العام',
        d.urgency || 'عادية',
        d.symptoms || '',
        'pending'
      );
      return sendJson(res, 201, { ok: true, message: 'تم استلام طلب الاستشارة بنجاح!' });
    } catch (err) {
      console.error('Error in consultation API:', err);
      return sendJson(res, 500, { ok: false, message: 'فشل معالجة الاستشارة.' });
    }
  }

  // 6. بيانات ومعلومات المركز الصحي (العنوان، ساعات العمل، الطوارئ، الحالة)
  if (req.method === 'GET' && url.pathname === '/api/medical/center-info') {
    const row = db.prepare('SELECT * FROM medical_center_info WHERE id = 1').get();
    return sendJson(res, 200, { ok: true, info: row || null });
  }

  if (req.method === 'POST' && url.pathname === '/api/medical/center-info') {
    try {
      const d = await parseJsonBody(req);
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO medical_center_info (id, name, address, hours, emergency, phone, is_open, status_text)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        d.name || '',
        d.address || '',
        d.hours || '',
        d.emergency || '',
        d.phone || '',
        d.isOpen ? 1 : 0,
        d.statusText || 'يستقبل الحالات الآن'
      );
      return sendJson(res, 200, { ok: true, message: 'تم حفظ وتحديث بيانات المركز بنجاح.' });
    } catch (err) {
      console.error('Error saving center info:', err);
      return sendJson(res, 500, { ok: false, message: 'فشل حفظ بيانات المركز.' });
    }
  }

  // 7. إدارة العيادات والأطباء
  if (req.method === 'GET' && url.pathname === '/api/medical/clinics') {
    const clinics = db.prepare('SELECT * FROM medical_clinics ORDER BY id ASC').all();
    return sendJson(res, 200, { ok: true, clinics });
  }

  if (req.method === 'POST' && url.pathname === '/api/medical/clinics') {
    try {
      const d = await parseJsonBody(req);
      const title = d.title || d.name || 'عيادة عامة';
      const doctor = d.doctor || 'طبيب مناوب';
      const timeSched = d.time_schedule || d.time || '08:00 ص - 02:00 م';
      const icon = d.icon || '🩺';
      const status = d.status || 'متاحة الآن';
      const isEr = d.is_er ? 1 : 0;
      const maxPatients = parseInt(d.max_patients || d.maxPatients || 20);
      const startTime = d.start_time || d.startTime || '09:00';
      const endTime = d.end_time || d.endTime || '14:00';
      const workDays = d.work_days || d.workDays || 'السبت - الخميس';

      if (d.id) {
        const stmt = db.prepare(`
          UPDATE medical_clinics 
          SET title = ?, doctor = ?, time_schedule = ?, icon = ?, status = ?, is_er = ?,
              max_patients = ?, start_time = ?, end_time = ?, work_days = ?
          WHERE id = ?
        `);
        stmt.run(title, doctor, timeSched, icon, status, isEr, maxPatients, startTime, endTime, workDays, d.id);
        return sendJson(res, 200, { ok: true, message: 'تم تحديث العيادة بنجاح.' });
      } else {
        const stmt = db.prepare(`
          INSERT INTO medical_clinics (title, doctor, time_schedule, icon, status, is_er, max_patients, start_time, end_time, work_days)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(title, doctor, timeSched, icon, status, isEr, maxPatients, startTime, endTime, workDays);
        return sendJson(res, 201, { ok: true, message: 'تم إضافة العيادة بنجاح.' });
      }
    } catch (err) {
      console.error('Error saving clinic:', err);
      return sendJson(res, 500, { ok: false, message: 'فشل حفظ العيادة.' });
    }
  }

  if (req.method === 'POST' && url.pathname === '/api/medical/clinics/delete') {
    try {
      const { id } = await parseJsonBody(req);
      db.prepare('DELETE FROM medical_clinics WHERE id = ?').run(id);
      return sendJson(res, 200, { ok: true, message: 'تم حذف العيادة.' });
    } catch (err) {
      return sendJson(res, 500, { ok: false, message: 'فشل حذف العيادة.' });
    }
  }

  // خدمة الصفحات الثابتة
  if (url.pathname === '/' || url.pathname === '/index.html' || url.pathname === '/login.html') {
    return serveStaticFile(res, path.join(__dirname, 'index.html'));
  }
  if (url.pathname === '/individual.html') {
    return serveStaticFile(res, path.join(__dirname, 'individual.html'));
  }
  if (url.pathname === '/admin.html') {
    return serveStaticFile(res, path.join(__dirname, 'admin.html'));
  }
  if (url.pathname === '/create-id.html') {
    return serveStaticFile(res, path.join(__dirname, 'create-id.html'));
  }
  if (url.pathname === '/my-id.html') {
    return serveStaticFile(res, path.join(__dirname, 'my-id.html'));
  }
  if (url.pathname === '/qrcode.min.js') {
    return serveStaticFile(res, path.join(__dirname, 'qrcode.min.js'), 'application/javascript; charset=utf-8');
  }
  if (url.pathname === '/organization.html') {
    return serveStaticFile(res, path.join(__dirname, 'organization.html'));
  }
  if (url.pathname === '/medical-booking.html') {
    return serveStaticFile(res, path.join(__dirname, 'medical-booking.html'));
  }
  if (url.pathname === '/medical-file.html') {
    return serveStaticFile(res, path.join(__dirname, 'medical-file.html'));
  }
  if (url.pathname === '/medical-results.html') {
    return serveStaticFile(res, path.join(__dirname, 'medical-results.html'));
  }
  if (url.pathname === '/telemedicine.html') {
    return serveStaticFile(res, path.join(__dirname, 'telemedicine.html'));
  }

  // مسار غير معروف
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('الصفحة غير موجودة');
});

server.listen(PORT, () => {
  console.log(`🚀 السيرفر يعمل الآن بنجاح على: http://localhost:${PORT}`);
  console.log(`📂 قاعدة البيانات جاهزة ومربوطة: ${DB_FILE}`);
});
