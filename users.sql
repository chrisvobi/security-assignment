DROP USER IF EXISTS 'loginuser';
CREATE USER 'loginuser' IDENTIFIED BY 'logpass';
GRANT SELECT ON pwd_mgr.login_users TO 'loginuser';

DROP USER IF EXISTS 'notesuser';
CREATE USER 'notesuser' IDENTIFIED BY 'notpass';
GRANT SELECT ON pwd_mgr.login_users TO 'notesuser';
GRANT SELECT,INSERT ON pwd_mgr.notes TO 'notesuser';

DROP USER IF EXISTS 'dashuser';
CREATE USER 'dashuser' IDENTIFIED BY 'dashpass';
GRANT SELECT ON pwd_mgr.login_users TO 'dashuser';
GRANT SELECT, INSERT, DELETE ON pwd_mgr.websites TO 'dashuser';

DROP USER IF EXISTS 'reguser';
CREATE USER 'reguser' IDENTIFIED BY 'regpass';
GRANT INSERT ON pwd_mgr.login_users TO 'reguser';

UPDATE pwd_mgr.login_users
SET PASSWORD = 'ab51495df31c5078c0374c8d87b6abe55b8bde0d6b96477c3a'
WHERE username = 'u1';

UPDATE pwd_mgr.websites
SET web_password = 'D27w5tAtuXSfqTDWfNHQVLN3Dz4M/yw='
WHERE webid = 1;