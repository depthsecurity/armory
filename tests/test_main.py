from armory import armory
import os
import unittest

try:
    from unittest import mock
    from unittest.mock import MagicMock, mock_open
except ImportError:
    # Python 2. =/
    import mock
    from mock import MagicMock, mock_open


class CheckAndCreateConfigs(unittest.TestCase):
    @mock.patch("armory.armory.generate_default_configs")
    @mock.patch("armory.armory.os.path")
    @mock.patch("armory.armory.os")
    def test_settings_folder_exists(self, mock_os, mock_path, mock_gen):
        def dir_exists(value):
            if value == armory.CONFIG_FOLDER:
                return True
            else:
                return False

        settings_path = os.path.join(armory.CONFIG_FOLDER, armory.CONFIG_FILE)
        mock_path.exists = MagicMock(side_effect=dir_exists)
        mock_path.join.return_value = settings_path
        with mock.patch.object(
            armory, "resource_string", wraps=armory.resource_string
        ) as mock_res:
            with mock.patch.object(armory, "open", mock_open()) as mopen:
                armory.check_and_create_configs()
                self.assertFalse(
                    mock_os.mkdir.called,
                    "Called os.mkdir even though the folder exists.",
                )
                self.assertTrue(
                    mock_path.join.called,
                    "Should have called os.path.join since the file doesn't exist.",
                )
                self.assertTrue(
                    mock_res.called,
                    "resource_string should have been called to get the default settings.",
                )
                mopen.assert_called_once_with(settings_path, "w")
                self.assertTrue(
                    mock_gen.called,
                    "Should have called generate_default_configs after creating {}.".format(
                        settings_path
                    ),
                )

    @mock.patch("armory.armory.generate_default_configs")
    @mock.patch("armory.armory.os.path")
    @mock.patch("armory.armory.os")
    def test_settings_donot_exist(self, mock_os, mock_path, mock_gen):
        settings_path = os.path.join(armory.CONFIG_FOLDER, armory.CONFIG_FILE)
        mock_path.exists.return_value = False
        mock_path.join.return_value = settings_path
        with mock.patch.object(
            armory, "resource_string", wraps=armory.resource_string
        ) as mock_res:
            with mock.patch.object(armory, "open", mock_open()) as mopen:
                armory.check_and_create_configs()
                self.assertTrue(
                    mock_os.mkdir.called,
                    "Called os.mkdir even though the folder exists.",
                )
                self.assertTrue(
                    mock_path.join.called,
                    "Should have called os.path.join since the file doesn't exist.",
                )
                self.assertTrue(
                    mock_res.called,
                    "resource_string should have been called to get the default settings.",
                )
                mopen.assert_called_once_with(settings_path, "w")
                self.assertTrue(
                    mock_gen.called,
                    "Should have called generate_default_configs after creating {}.".format(
                        settings_path
                    ),
                )

    @mock.patch("armory.armory.generate_default_configs")
    @mock.patch("armory.armory.os.path")
    @mock.patch("armory.armory.os")
    def test_settings_exist(self, mock_os, mock_path, mock_gen):
        settings_path = os.path.join(armory.CONFIG_FOLDER, armory.CONFIG_FILE)
        mock_path.exists.return_value = True
        mock_path.join.return_value = settings_path
        with mock.patch.object(
            armory, "resource_string", wraps=armory.resource_string
        ) as mock_res:
            with mock.patch.object(armory, "open", mock_open()) as mopen:
                armory.check_and_create_configs()
                self.assertFalse(
                    mock_os.mkdir.called,
                    "Called os.mkdir even though the folder exists.",
                )
                self.assertTrue(
                    mock_path.join.called,
                    "Should have called for the check to see if {} exists.".format(
                        settings_path
                    ),
                )
                self.assertFalse(
                    mock_res.called,
                    "resource_string should not have been called since the file already exists.",
                )
                self.assertFalse(mopen.called, "open() should not have been called.")
                self.assertFalse(
                    mock_gen.called, "Should not have called generate_default_configs. "
                )


class GetConfigOptions(unittest.TestCase):
    @mock.patch("armory.armory.os.path")
    def test_config_folder_nofile(self, mock_path):
        settings_path = os.path.join(armory.CONFIG_FOLDER, armory.CONFIG_FILE)
        mock_path.exists.return_value = False
        mock_path.join.return_value = settings_path
        self.assertRaises(ValueError, armory.get_config_options())
        self.assertTrue(mock_path.join.called, "os.path.join should have been called.")
        self.assertTrue(
            mock_path.exists.called, "os.path.exists should have been called."
        )
