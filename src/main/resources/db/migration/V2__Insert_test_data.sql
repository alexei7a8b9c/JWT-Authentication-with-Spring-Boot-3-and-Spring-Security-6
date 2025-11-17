-- Вставка тестовых пользователей с простыми паролями
INSERT INTO users (username, password, email, role) VALUES
                                                        (
                                                            'admin',
                                                            'admin123', -- простой пароль
                                                            'admin@example.com',
                                                            'ROLE_ADMIN'
                                                        ),
                                                        (
                                                            'user1',
                                                            'user123', -- простой пароль
                                                            'user1@example.com',
                                                            'ROLE_USER'
                                                        ),
                                                        (
                                                            'user2',
                                                            'user123', -- простой пароль
                                                            'user2@example.com',
                                                            'ROLE_USER'
                                                        ),
                                                        (
                                                            'testuser',
                                                            'test123', -- простой пароль
                                                            'test@example.com',
                                                            'ROLE_USER'
                                                        );